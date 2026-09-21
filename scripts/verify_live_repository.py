#!/usr/bin/env python3
"""Read-only verification of the deployed, pinned DailyBeat repository and APK.

Requires the same fdroidserver/JDK/Android build-tools as build_repository.py.
No signing credentials are needed. Downloads stay in a temporary directory and
are bounded before fdroidserver parses them; only the exact GitHub Pages origin
and reviewed filenames are requested, with no redirects or third-party mirrors.
"""
from __future__ import annotations

import argparse
import importlib.metadata
from pathlib import Path
import sys
import tempfile
import time
import urllib.request
from unittest.mock import patch
import zipfile

import build_repository as builder


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise builder.BuildError("The live repository redirected; verification refused.")


def download_public(url: str, destination: Path, maximum: int, deadline: float) -> None:
    builder.require(url == builder.REPOSITORY_URL + "/" + destination.name,
                    "Live download left the exact pinned repository path.")
    request = urllib.request.Request(url, headers={
        "User-Agent": "DailyBeat-Live-Repository-Verification/1",
        "Accept-Encoding": "identity",
    })
    opener = urllib.request.build_opener(NoRedirects())
    with opener.open(request, timeout=15) as response, destination.open("xb") as target:
        builder.require(response.geturl() == url and response.status == 200,
                        "Live repository did not return the requested file.")
        builder.require(response.headers.get("Content-Encoding", "identity") == "identity",
                        "Live repository returned an unexpected content encoding.")
        length = response.headers.get("Content-Length")
        if length is not None:
            builder.require(length.isdigit() and 0 < int(length) <= maximum,
                            "Live repository file exceeds its permitted size.")
        total = 0
        while True:
            builder.require(time.monotonic() < deadline, "Live repository exceeded the verification deadline.")
            block = response.read1(min(maximum + 1, 1024 * 1024))
            if not block:
                break
            total += len(block)
            builder.require(total <= maximum, "Live repository file exceeds its permitted size.")
            target.write(block)
        builder.require(total > 0 and (length is None or total == int(length)),
                        "Live repository returned an empty or incomplete file.")


def check_index_archive(path: Path, expected_payload: str) -> None:
    # JAR signatures cannot prevent excessive allocation before signature verification.
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        builder.require(0 < len(members) <= 32 and
                        sum(member.file_size for member in members) <= builder.MAX_JSON_BYTES,
                        "Live index archive exceeds its unpacked size limit.")
        names = [member.filename for member in members]
        builder.require(len(set(names)) == len(names) and
                        [name for name in names if not name.startswith("META-INF/")] == [expected_payload],
                        "Live index archive has unexpected or duplicate payloads.")
        builder.require(not any(member.flag_bits & 1 for member in members),
                        "Live index archive must not contain encrypted entries.")


def verify(root: Path) -> dict:
    from fdroidserver import common, index, net

    builder.require(importlib.metadata.version("fdroidserver") == "2.4.5",
                    "Live verification requires fdroidserver==2.4.5.")
    release = builder.validate_release(builder.read_json(root / "release.json"))
    repository = builder.validate_repository(builder.read_json(root / "repository.json"))
    metadata = builder.load_metadata(root, release)
    tools = builder.android_tools()
    common.config = {"jarsigner": builder.java_tool("jarsigner")}
    apk_name = f"{builder.PACKAGE}_{release['versionCode']}.apk"
    files = {
        "index-v1.jar": 4 * 1024 * 1024,
        "index-v1.json": builder.MAX_JSON_BYTES,
        "entry.jar": 1024 * 1024,
        "entry.json": 1024 * 1024,
        "index-v2.json": builder.MAX_JSON_BYTES,
        "index.html": 2 * 1024 * 1024,
        "index.png": 2 * 1024 * 1024,
        apk_name: builder.MAX_APK_BYTES,
    }
    with tempfile.TemporaryDirectory(prefix="dailybeat-live-verify-") as temporary:
        repo = Path(temporary)
        deadline = time.monotonic() + 300
        fetched = {}
        for name, limit in files.items():
            url = repository["url"] + "/" + name
            path = repo / name
            download_public(url, path, limit, deadline)
            fetched[url] = path
        check_index_archive(repo / "index-v1.jar", "index-v1.json")
        check_index_archive(repo / "entry.jar", "entry.json")

        def approved_file(url):
            builder.require(url in fetched, "F-Droid requested an unreviewed live index path.")
            return fetched[url]

        def bounded_http_get(url, etag=None, timeout=600):
            builder.require(etag is None, "Live verification must fetch fresh index data.")
            return approved_file(url).read_bytes(), None

        def bounded_mirrors(mirrors, local_filename=None):
            builder.require(local_filename is None and len(mirrors) == 1,
                            "Live verification does not permit alternate mirrors.")
            return str(approved_file(mirrors[0]["url"]))

        # Use F-Droid's real client parsing/signature path on the exact bytes fetched above.
        # Replace only its unbounded network transport; no signature verification is mocked.
        url = repository["url"] + "?fingerprint=" + repository["fingerprint"]
        with patch.object(net, "http_get", bounded_http_get), patch.object(net, "download_using_mirrors", bounded_mirrors):
            v1, _ = index.download_repo_index_v1(url, verify_fingerprint=True, timeout=15)
            v2, _ = index.download_repo_index_v2(url, verify_fingerprint=True)
        builder.verify_index_metadata(v1, v2, release, metadata)
        builder.verify_indexes(repo, release, repository, tools, metadata)
    return {"version": release["version"], "versionCode": release["versionCode"],
            "fingerprint": repository["fingerprint"], "apkSha256": release["apkSha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = verify(args.root)
        print(f"Live F-Droid v1/v2 indexes and APK verified: DailyBeat {result['version']} (code {result['versionCode']}).")
        print("Repository fingerprint:", result["fingerprint"])
        print("APK SHA256:", result["apkSha256"])
        return 0
    except builder.BuildError as error:
        print(str(error), file=sys.stderr)
    except Exception:
        print("Live repository verification failed; trust or availability was not confirmed.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
