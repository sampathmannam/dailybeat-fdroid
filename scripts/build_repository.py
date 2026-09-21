#!/usr/bin/env python3
"""Index the pinned, already signed DailyBeat APK; publish only an explicit file allowlist.

Requires fdroidserver==2.4.5, PyYAML, Python 3.11+, a JDK and Android build-tools.
Build-tools 35.0.0 are preferred; other installed stable versions support local verification.
The repository key is separate from the APK key. Its password is read only from
DAILYBEAT_REPO_PASSWORD. No command receives a password in its arguments.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request


PACKAGE = "com.dailybeat.app"
APK_SIGNER = "44510de2f642f54f8f046fc05b44227a15a2e8473460594b106e976862d3436f"
REPOSITORY_URL = "https://sampathmannam.github.io/dailybeat-fdroid/fdroid/repo"
MAX_APK_BYTES = 150 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
PUBLIC_INDEX_FILES = {
    "index-v1.jar", "index-v1.json", "index-v2.json",
    "entry.jar", "entry.json", "index.html", "index.css", "index.png",
}
DISCARDED_GENERATED_FILES = {"index.jar", "index.xml", "status/running.json", "status/update.json"}
ANTI_FEATURES = {"NonFreeNet", "TetheredNet", "Tracking"}


class BuildError(Exception):
    """An intentional, credential-free build diagnostic."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def read_json(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "Expected a regular JSON input file.")
    require(path.stat().st_size <= MAX_JSON_BYTES, "JSON input exceeds its size limit.")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "JSON input must be an object.")
    return value


def fingerprint(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None,
            "Certificate/checksum must be exactly 64 hexadecimal characters.")
    return value.lower()


def validate_release(value: dict) -> dict:
    keys = {"version", "versionCode", "sourceCommit", "apkUrl", "apkSha256", "apkSignerSha256", "packageName"}
    require(set(value) == keys, "Unexpected or missing release metadata fields.")
    require(isinstance(value["version"], str) and
            re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value["version"]) is not None,
            "Invalid release version.")
    require(type(value["versionCode"]) is int and 1 <= value["versionCode"] <= 2_100_000_000,
            "Invalid Android version code.")
    require(isinstance(value["sourceCommit"], str) and
            re.fullmatch(r"[0-9a-f]{40}", value["sourceCommit"]) is not None, "Invalid immutable source commit.")
    require(value["packageName"] == PACKAGE, "Unexpected Android package.")
    require(fingerprint(value["apkSignerSha256"]) == APK_SIGNER, "Unexpected permanent APK signing certificate.")
    fingerprint(value["apkSha256"])
    version = value["version"]
    expected = (f"https://github.com/sampathmannam/dailybeat/releases/download/"
                f"fdroid-v{version}/DailyBeat-FDroid-v{version}.apk")
    require(value["apkUrl"] == expected, "APK URL must match the exact pinned Google-free release asset.")
    return value


def validate_repository(value: dict) -> dict:
    require(set(value) == {"name", "url", "description", "fingerprint"}, "Unexpected repository metadata fields.")
    require(value["url"] == REPOSITORY_URL, "Unexpected repository address.")
    for field, limit in (("name", 120), ("description", 2000)):
        text = value[field]
        # fdroidserver's generated catalog interpolates these values into HTML attributes.
        require(isinstance(text, str) and 0 < len(text) <= limit and
                not any(ord(c) < 32 or c in '<>"' for c in text), "Invalid repository display text.")
    require(fingerprint(value["fingerprint"]) != APK_SIGNER, "The repository must have its own signing key.")
    return value


def validate_metadata(value: dict, release: dict) -> dict:
    require(isinstance(value, dict), "App metadata must be an object.")
    source = "https://github.com/sampathmannam/dailybeat"
    expected = {
        "SourceCode": f"{source}/tree/{release['sourceCommit']}",
        "Changelog": f"{source}/blob/{release['sourceCommit']}/CHANGELOG.md",
        "CurrentVersion": release["version"], "CurrentVersionCode": release["versionCode"],
        "License": "GPL-3.0-only", "AllowedAPKSigningKeys": APK_SIGNER,
    }
    for field, wanted in expected.items():
        require(value.get(field) == wanted, f"App metadata {field} differs from the pinned release.")
    disclosures = value.get("AntiFeatures")
    require(isinstance(disclosures, dict) and set(disclosures) == ANTI_FEATURES,
            "App metadata must retain all three network/privacy disclosures.")
    for description in disclosures.values():
        require(isinstance(description, dict) and set(description) == {"en-US"} and
                isinstance(description["en-US"], str) and 20 <= len(description["en-US"]) <= 2000,
                "Each Anti-Feature must retain its explanatory English disclosure.")
    return value


def load_metadata(root: Path, release: dict) -> dict:
    import yaml

    path = root / "metadata" / f"{PACKAGE}.yml"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536,
            "Expected bounded regular app metadata.")
    metadata = validate_metadata(yaml.safe_load(path.read_text(encoding="utf-8")), release)
    localized = {}
    for field, limit in (("name", 50), ("summary", 80), ("description", 4000)):
        text_path = root / "metadata" / PACKAGE / "en-US" / f"{field}.txt"
        require(text_path.is_file() and not text_path.is_symlink() and text_path.stat().st_size <= limit * 4,
                "Required localized app metadata is missing or oversized.")
        text = text_path.read_text(encoding="utf-8")
        if field in ("name", "summary"):
            text = text.strip("\n")
        require(0 < len(text) <= limit, "Localized text exceeds the index protocol limit.")
        localized[field] = text
    return {"app": metadata, "localized": localized}


def verify_index_metadata(v1: dict, v2: dict, release: dict, expected: dict) -> None:
    app = expected["app"]
    apps = v1.get("apps")
    require(isinstance(apps, list) and len(apps) == 1 and apps[0].get("packageName") == PACKAGE,
            "Signed v1 app metadata contains an unexpected package set.")
    first = apps[0]
    second = v2["packages"][PACKAGE]["metadata"]
    for field in ("sourceCode", "changelog", "license"):
        original = field[:1].upper() + field[1:]
        require(first.get(field) == app[original] and second.get(field) == app[original],
                f"Signed app metadata {field} differs from reviewed metadata.")
    require(first.get("suggestedVersionName") == release["version"] and
            first.get("suggestedVersionCode") == str(release["versionCode"]),
            "Signed current-version recommendation differs from the pinned release.")
    require(set(first.get("antiFeatures", [])) == ANTI_FEATURES,
            "Signed v1 index lost network/privacy disclosures.")
    version2 = v2["packages"][PACKAGE]["versions"][release["apkSha256"]]
    require(version2.get("antiFeatures") == app["AntiFeatures"] and not version2.get("releaseChannels"),
            "Signed v2 disclosure/current release metadata mismatch.")
    for field, text in expected["localized"].items():
        require(first.get("localized", {}).get("en-US", {}).get(field) == text and
                second.get(field, {}).get("en-US") == text,
                f"Signed localized {field} differs from reviewed text.")


def validate_download_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in DOWNLOAD_HOSTS and
            parsed.username is None and parsed.password is None and parsed.port in (None, 443) and
            not parsed.fragment and not any(ord(c) < 32 for c in url),
            "Download redirect left the approved HTTPS GitHub asset hosts.")


class ApprovedRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, request, response, code, message, headers, newurl):
        validate_download_url(newurl)
        return super().redirect_request(request, response, code, message, headers, newurl)


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_checksum(path: Path, expected: str) -> None:
    require(path.is_file() and not path.is_symlink(), "APK is not a regular file.")
    require(0 < path.stat().st_size <= MAX_APK_BYTES, "APK exceeds its permitted size.")
    require(sha256(path) == fingerprint(expected), "APK checksum does not match the pinned release.")


def download_apk(url: str, destination: Path, expected: str) -> None:
    validate_download_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "DailyBeat-FDroid-Repository/1", "Accept-Encoding": "identity"})
    opener = urllib.request.build_opener(ApprovedRedirects())
    started = time.monotonic()
    try:
        with opener.open(request, timeout=30) as response, destination.open("xb") as target:
            validate_download_url(response.geturl())
            require(response.status == 200, "Release download did not return HTTP 200.")
            length = response.headers.get("Content-Length")
            if length is not None:
                require(length.isdigit() and 0 < int(length) <= MAX_APK_BYTES, "Release download has an invalid size.")
            total = 0
            while True:
                require(time.monotonic() - started < 300, "Release download exceeded its total time limit.")
                # One underlying read per iteration lets the total deadline interrupt a
                # server that drips bytes just fast enough to avoid the socket timeout.
                block = response.read1(1024 * 1024)
                if not block:
                    break
                total += len(block)
                require(total <= MAX_APK_BYTES, "Release download exceeded its size limit.")
                target.write(block)
        verify_checksum(destination, expected)
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 120) -> str:
    # Do not print subprocess output: index/signing tools may include private config paths or
    # environment-derived diagnostics. Successful output is consumed only for explicit checks.
    try:
        result = subprocess.run(command, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise BuildError(f"Required tool failed: {Path(command[0]).name}.") from None
    return result.stdout


def android_tools() -> dict[str, str]:
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    require(bool(sdk), "Set ANDROID_HOME to the Android SDK directory.")
    build_tools = Path(sdk) / "build-tools"
    require(build_tools.is_dir(), "Android SDK build-tools are required.")
    candidates = sorted((p for p in build_tools.iterdir() if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", p.name)),
                        key=lambda p: tuple(map(int, p.name.split("."))), reverse=True)
    preferred = build_tools / "35.0.0"
    if preferred in candidates:
        candidates.remove(preferred)
        candidates.insert(0, preferred)
    for base in candidates:
        tools = {name: str(base / name) for name in ("apksigner", "aapt")}
        if all(Path(path).is_file() and os.access(path, os.X_OK) for path in tools.values()):
            return tools
    raise BuildError("Install Android SDK build-tools with aapt and apksigner.")


def java_tool(name: str) -> str:
    java_home = os.environ.get("JAVA_HOME")
    path = str(Path(java_home) / "bin" / name) if java_home else shutil.which(name)
    require(bool(path) and Path(path).is_file(), f"A JDK with {name} is required.")
    return str(path)


def verify_apk(apk: Path, release: dict, tools: dict[str, str]) -> None:
    verify_checksum(apk, release["apkSha256"])
    signed = run([tools["apksigner"], "verify", "--verbose", "--print-certs", str(apk)])
    signers = re.findall(r"^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$", signed, re.MULTILINE)
    require([s.lower() for s in signers] == [APK_SIGNER], "APK signer does not match the permanent certificate.")
    require(re.search(r"^Verified using v[23] scheme.*: true$", signed, re.MULTILINE) is not None,
            "APK lacks a verified modern APK signing block.")
    badging = run([tools["aapt"], "dump", "badging", str(apk)])
    identity = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", badging, re.MULTILINE)
    require(identity is not None, "Unable to verify the APK manifest identity.")
    require(identity.groups() == (PACKAGE, str(release["versionCode"]), release["version"]),
            "APK package/version differs from the pinned release.")


def public_path(relative: str, apk_name: str) -> bool:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts) or "\\" in relative:
        return False
    if relative in PUBLIC_INDEX_FILES or relative == apk_name:
        return True
    if re.fullmatch(r"icons(?:-[0-9]{1,5})?/[A-Za-z0-9_.-]+\.png", relative):
        return True
    return re.fullmatch(
        # fdroidserver content-addresses artwork with URL-safe Base64 SHA-256,
        # whose 32-byte digest has exactly 43 characters and one padding '='.
        r"com\.dailybeat\.app/[a-z]{2,3}(?:-[A-Za-z0-9]+)*(?:/[A-Za-z]+Screenshots)?/"
        r"(?:[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+_[A-Za-z0-9_-]{43}=)\.(?:png|jpg|jpeg|webp)",
        relative,
    ) is not None


def copy_public_repository(source: Path, destination: Path, apk_name: str) -> None:
    require(not destination.exists(), "Public output already exists.")
    selected = []
    for current, directories, files in os.walk(source, followlinks=False):
        for name in directories + files:
            require(not (Path(current) / name).is_symlink(), "Repository output contains a filesystem link.")
        for name in files:
            path = Path(current) / name
            relative = path.relative_to(source).as_posix()
            if public_path(relative, apk_name):
                require(path.is_file(), "Repository output is not a regular file.")
                selected.append((path, relative))
            # Status contains private tool details. Legacy v0 has no supported verification
            # here and is deliberately not published; only verified v1 and v2 are offered.
            elif relative not in DISCARDED_GENERATED_FILES:
                # Expose only a bounded, escaped relative pathname, never file contents.
                raise BuildError(f"Unexpected generated file {json.dumps(relative[:200])}; publication refused.")
    for path, relative in selected:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def verify_json_companion(path: Path, signed: dict) -> None:
    require(read_json(path) == signed, "Public JSON companion differs from its verified signed JAR.")


def verify_indexes(repo: Path, release: dict, repository: dict, tools: dict[str, str], metadata: dict) -> None:
    from fdroidserver import common, index

    common.config = {"jarsigner": java_tool("jarsigner")}
    pinned = fingerprint(repository["fingerprint"])
    # Protocol v1 mandates legacy JAR algorithms; use fdroidserver's compatibility verifier.
    v1, _, _ = index.get_index_from_jar(str(repo / "index-v1.jar"), pinned, allow_deprecated=True)
    entry, _, _ = index.get_index_from_jar(str(repo / "entry.jar"), pinned)
    verify_json_companion(repo / "index-v1.json", v1)
    verify_json_companion(repo / "entry.json", entry)
    require(entry["index"]["name"] == "/index-v2.json", "Signed entry points to an unexpected index.")
    v2_path = repo / "index-v2.json"
    require(sha256(v2_path) == fingerprint(entry["index"]["sha256"]), "Signed v2 index checksum mismatch.")
    require(v2_path.stat().st_size == entry["index"]["size"], "Signed v2 index size mismatch.")
    v2 = read_json(v2_path)
    apk_name = f"{PACKAGE}_{release['versionCode']}.apk"
    for data in (v1, v2):
        require(data["repo"]["address"] == repository["url"], "Signed index repository URL mismatch.")
        require(set(data["packages"]) == {PACKAGE}, "Signed index contains an unexpected package set.")
    versions = v1["packages"][PACKAGE]
    require(len(versions) == 1, "Expected exactly one reviewed APK version.")
    first = versions[0]
    require(first["apkName"] == apk_name and first["versionCode"] == release["versionCode"] and
            first["versionName"] == release["version"] and first["hashType"] == "sha256" and
            first["hash"] == release["apkSha256"] and first["signer"] == APK_SIGNER,
            "Signed v1 package identity/checksum mismatch.")
    versions2 = v2["packages"][PACKAGE]["versions"]
    require(set(versions2) == {release["apkSha256"]}, "Signed v2 APK set mismatch.")
    second = versions2[release["apkSha256"]]
    require(second["file"]["name"] == f"/{apk_name}" and second["file"]["sha256"] == release["apkSha256"] and
            second["manifest"]["versionCode"] == release["versionCode"] and
            second["manifest"]["versionName"] == release["version"] and
            second["manifest"]["signer"]["sha256"] == [APK_SIGNER], "Signed v2 package identity/checksum mismatch.")
    require(second["file"]["size"] == (repo / apk_name).stat().st_size, "Signed APK size mismatch.")
    verify_index_metadata(v1, v2, release, metadata)
    verify_apk(repo / apk_name, release, tools)
    for path in repo.rglob("*"):
        require(not path.is_symlink(), "Public repository contains a filesystem link.")
        if not path.is_dir():
            require(public_path(path.relative_to(repo).as_posix(), apk_name), "Public output contains an unapproved file.")
    require((repo / "index.html").is_file() and (repo / "index.png").is_file(), "Repository catalog/QR is missing.")


def build(root: Path, output: Path, keystore: Path, release: dict, repository: dict, tools: dict[str, str]) -> Path:
    import yaml

    reviewed_metadata = load_metadata(root, release)
    require(bool(os.environ.get("DAILYBEAT_REPO_PASSWORD")), "Set DAILYBEAT_REPO_PASSWORD for repository signing.")
    require(keystore.is_file() and not keystore.is_symlink(), "Repository keystore must be an external regular file.")
    require(not keystore.resolve().is_relative_to(output.resolve()), "Keep the keystore outside the build output.")
    if output.exists():
        require(output.is_dir() and not output.is_symlink() and not any(output.iterdir()), "Build output must be a fresh or empty directory.")
    else:
        output.mkdir(parents=True, mode=0o700)
    require(output.resolve() != root.resolve() and output.resolve() not in root.resolve().parents,
            "Build output must not be the source tree or its ancestor.")
    fdroid = shutil.which("fdroid")
    require(bool(fdroid) and run([fdroid, "--version"]).strip() == "2.4.5", "fdroidserver CLI 2.4.5 is required.")
    certificate = run([java_tool("keytool"), "-exportcert", "-rfc", "-alias", "dailybeat-repo",
                       "-keystore", str(keystore.resolve()), "-storepass:env", "DAILYBEAT_REPO_PASSWORD"])
    import ssl
    certificate_bytes = ssl.PEM_cert_to_DER_cert(certificate)
    require(hashlib.sha256(certificate_bytes).hexdigest() == fingerprint(repository["fingerprint"]),
            "Repository keystore certificate differs from the pinned repository fingerprint.")
    apk_name = f"{PACKAGE}_{release['versionCode']}.apk"
    public_repo = output / "site" / "fdroid" / "repo"
    with tempfile.TemporaryDirectory(prefix=".private-index-", dir=output) as private:
        working = Path(private)
        (working / "repo").mkdir()
        metadata = root / "metadata"
        require(metadata.is_dir() and not metadata.is_symlink(), "Tracked metadata is missing.")
        require(not any(p.is_symlink() for p in metadata.rglob("*")), "Metadata must not contain filesystem links.")
        shutil.copytree(metadata, working / "metadata")
        icon = root / "assets" / "icon.png"
        require(icon.is_file() and not icon.is_symlink(), "Tracked repository icon is missing.")
        shutil.copyfile(icon, working / "icon.png")
        config = {
            "repo_name": repository["name"], "repo_url": repository["url"],
            "repo_description": repository["description"], "repo_icon": "icon.png",
            "repo_keyalias": "dailybeat-repo", "keystore": str(keystore.resolve()),
            "keystorepass": {"env": "DAILYBEAT_REPO_PASSWORD"}, "keypass": {"env": "DAILYBEAT_REPO_PASSWORD"},
            "sdk_path": os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT"),
            "apksigner": tools["apksigner"], "aapt": tools["aapt"],
            "jarsigner": java_tool("jarsigner"), "keytool": java_tool("keytool"),
            "archive_older": 0, "make_current_version_link": False,
        }
        config_file = working / "config.yml"
        config_file.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")
        config_file.chmod(0o600)
        apk = working / "repo" / apk_name
        download_apk(release["apkUrl"], apk, release["apkSha256"])
        verify_apk(apk, release, tools)
        run([fdroid, "update", "--clean"], cwd=working, timeout=600)
        candidate = working / "public"
        copy_public_repository(working / "repo", candidate, apk_name)
        verify_indexes(candidate, release, repository, tools, reviewed_metadata)
        public_repo.parent.mkdir(parents=True)
        candidate.rename(public_repo)
    return public_repo


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keystore", type=Path)
    parser.add_argument("--verify-only", action="store_true", help="Verify output/site/fdroid/repo without a signing key.")
    args = parser.parse_args()
    try:
        require(importlib.metadata.version("fdroidserver") == "2.4.5", "Python requires fdroidserver==2.4.5.")
        release = validate_release(read_json(args.root / "release.json"))
        repository = validate_repository(read_json(args.root / "repository.json"))
        tools = android_tools()
        if args.verify_only:
            verify_indexes(args.output / "site" / "fdroid" / "repo", release, repository, tools,
                           load_metadata(args.root, release))
            print("Signed repository indexes, APK identity, certificates and checksums verified.")
        else:
            require(args.keystore is not None, "--keystore is required to build.")
            published = build(args.root, args.output, args.keystore, release, repository, tools)
            print(f"Verified public repository: {published}")
        return 0
    except BuildError as error:
        print(str(error), file=sys.stderr)
    except Exception:
        # Do not echo raw provider/tool/parser errors, which can include environment contents.
        print("Repository build/verification failed; no deployment is authorized.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
