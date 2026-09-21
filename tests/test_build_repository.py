"""Adversarial input/publication tests; no network, production key, or external writes."""
import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_repository.py"
spec = importlib.util.spec_from_file_location("build_repository", SCRIPT)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def release():
    return {
        "version": "4.3.4", "versionCode": 38,
        "sourceCommit": "96891eedc9556454d2c1ed8f9a22236ebdc511f4",
        "apkUrl": "https://github.com/sampathmannam/dailybeat/releases/download/fdroid-v4.3.4/DailyBeat-FDroid-v4.3.4.apk",
        "apkSha256": "8048c18dedd42c70180c9b1e981d9b320cb866499b70d17f76f1c23af7f00bfa",
        "apkSignerSha256": builder.APK_SIGNER, "packageName": builder.PACKAGE,
    }


def repository():
    return {"name": "DailyBeat — Google-free", "description": "Official Google-free DailyBeat updates.",
            "url": builder.REPOSITORY_URL, "fingerprint": "ab" * 32}


def metadata():
    source = "https://github.com/sampathmannam/dailybeat"
    return {
        "SourceCode": f"{source}/tree/{release()['sourceCommit']}",
        "Changelog": f"{source}/blob/{release()['sourceCommit']}/CHANGELOG.md",
        "CurrentVersion": "4.3.4", "CurrentVersionCode": 38, "License": "GPL-3.0-only",
        "AllowedAPKSigningKeys": builder.APK_SIGNER,
        "AntiFeatures": {key: {"en-US": "A complete explanation of this network privacy limitation."}
                         for key in builder.ANTI_FEATURES},
    }


def signed_metadata():
    tracked = metadata()
    localized = {"name": "DailyBeat", "summary": "A journal.", "description": "<p>Privacy disclosure.</p>\n"}
    fields = {field[:1].lower() + field[1:]: tracked[field] for field in ("SourceCode", "Changelog", "License")}
    v1 = {"apps": [dict(fields, packageName=builder.PACKAGE, suggestedVersionName="4.3.4",
                        suggestedVersionCode="38", antiFeatures=sorted(builder.ANTI_FEATURES),
                        localized={"en-US": dict(localized)})]}
    v2 = {"packages": {builder.PACKAGE: {"metadata": dict(fields, **{
        field: {"en-US": text} for field, text in localized.items()}), "versions": {
            release()["apkSha256"]: {"antiFeatures": copy.deepcopy(tracked["AntiFeatures"])}}}}}
    return v1, v2, {"app": tracked, "localized": localized}


class BuildRepositoryTest(unittest.TestCase):
    def test_pinned_release_and_repository_are_accepted(self):
        self.assertEqual(builder.validate_release(release())["versionCode"], 38)
        self.assertEqual(builder.validate_repository(repository())["url"], builder.REPOSITORY_URL)

    def test_release_inputs_reject_wrong_identity_checksum_types_and_ambiguous_versions(self):
        for field, values in {
            "version": ["4.3.4/../../private", "04.3.4", "4.3", 434],
            "versionCode": [0, -1, True, "38", 2_100_000_001],
            "sourceCommit": ["main", "a" * 39, "a" * 41],
            "packageName": ["com.dailybeat.app.qa", "com.attacker.app"],
            "apkSha256": ["aa", "g" * 64, " " + "a" * 64],
            "apkSignerSha256": ["ab" * 32, None],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(builder.BuildError):
                    builder.validate_release(dict(release(), **{field: value}))
        with self.assertRaises(builder.BuildError):
            builder.validate_release(dict(release(), unexpected="secret"))

    def test_only_exact_google_free_release_url_is_accepted(self):
        for url in (
            release()["apkUrl"] + "?token=secret", release()["apkUrl"] + "#fragment",
            release()["apkUrl"].replace("github.com", "github.com.evil.example"),
            release()["apkUrl"].replace("https://", "http://"),
            release()["apkUrl"].replace("github.com", "credentials@github.com"),
            release()["apkUrl"].replace("fdroid-v4.3.4", "v4.3.4"),
            release()["apkUrl"].replace("4.3.4", "4.3.3"),
            "file:///etc/passwd",
        ):
            with self.subTest(url=url), self.assertRaises(builder.BuildError):
                builder.validate_release(dict(release(), apkUrl=url))

    def test_redirects_cannot_escape_trusted_https_hosts(self):
        for url in ("http://release-assets.githubusercontent.com/asset", "https://github.com.evil.test/asset",
                    "https://user:password@github.com/asset", "https://github.com:444/asset",
                    "file:///private/key", "https://127.0.0.1/asset", "https://github.com/asset#fragment"):
            with self.subTest(url=url), self.assertRaises(builder.BuildError):
                builder.validate_download_url(url)
        builder.validate_download_url("https://release-assets.githubusercontent.com/asset?signature=opaque")
        with self.assertRaises(builder.BuildError):
            builder.ApprovedRedirects().redirect_request(None, None, 302, "Found", {}, "https://attacker.example/file")

    def test_repository_certificate_must_be_separate_and_catalog_text_safe(self):
        for change in ({"fingerprint": builder.APK_SIGNER}, {"fingerprint": "invalid"},
                       {"url": builder.REPOSITORY_URL + "/../other"}, {"name": '<img src=x onerror="bad">'},
                       {"description": "bad\ncontrol"}):
            with self.subTest(change=change), self.assertRaises(builder.BuildError):
                builder.validate_repository(dict(repository(), **change))

    def test_metadata_binds_source_version_license_signer_and_disclosures(self):
        builder.validate_metadata(metadata(), release())
        for change in ({"SourceCode": "https://github.com/sampathmannam/dailybeat/tree/main"},
                       {"Changelog": metadata()["Changelog"].replace(release()["sourceCommit"], "main")},
                       {"CurrentVersion": "4.3.3"}, {"CurrentVersionCode": 37}, {"License": "MIT"},
                       {"AllowedAPKSigningKeys": "ab" * 32}, {"AntiFeatures": {}},
                       {"AntiFeatures": {key: {"en-US": ""} for key in builder.ANTI_FEATURES}}):
            with self.subTest(change=change), self.assertRaises(builder.BuildError):
                builder.validate_metadata(dict(metadata(), **change), release())

    def test_signed_metadata_must_preserve_reviewed_app_and_privacy_text(self):
        v1, v2, expected = signed_metadata()
        builder.verify_index_metadata(v1, v2, release(), expected)
        for field, bad in (("sourceCode", "https://attacker.example/source"), ("changelog", "main"),
                           ("license", "MIT"), ("suggestedVersionName", "4.3.3"),
                           ("suggestedVersionCode", "37"), ("antiFeatures", []),
                           ("localized", {"en-US": {"description": "Privacy omitted"}})):
            changed = copy.deepcopy(v1)
            changed["apps"][0][field] = bad
            with self.subTest(version=1, field=field), self.assertRaises(builder.BuildError):
                builder.verify_index_metadata(changed, v2, release(), expected)
        for field, bad in (("sourceCode", "main"), ("changelog", "main"), ("license", "MIT"),
                           ("description", {"en-US": "Privacy omitted"})):
            changed = copy.deepcopy(v2)
            changed["packages"][builder.PACKAGE]["metadata"][field] = bad
            with self.subTest(version=2, field=field), self.assertRaises(builder.BuildError):
                builder.verify_index_metadata(v1, changed, release(), expected)
        for field, bad in (("antiFeatures", {}), ("releaseChannels", ["Beta"])):
            changed = copy.deepcopy(v2)
            changed["packages"][builder.PACKAGE]["versions"][release()["apkSha256"]][field] = bad
            with self.subTest(version=2, field=field), self.assertRaises(builder.BuildError):
                builder.verify_index_metadata(v1, changed, release(), expected)

    def test_checksum_rejects_modified_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "release.apk"
            apk.write_bytes(b"test signed fixture")
            digest = builder.sha256(apk)
            builder.verify_checksum(apk, digest)
            apk.write_bytes(b"modified fixture")
            with self.assertRaises(builder.BuildError):
                builder.verify_checksum(apk, digest)

    def test_public_json_companions_must_match_verified_jar_payloads(self):
        signed = {"repo": {"address": builder.REPOSITORY_URL}, "packages": {builder.PACKAGE: []}}
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("index-v1.json", "entry.json"):
                with self.subTest(companion=name):
                    path = Path(tmp) / name
                    path.write_text(json.dumps(signed, indent=2))
                    builder.verify_json_companion(path, signed)
                    path.write_text(json.dumps(dict(signed, unexpected="tampered")))
                    with self.assertRaises(builder.BuildError):
                        builder.verify_json_companion(path, signed)

    def test_apk_signature_and_manifest_identity_are_both_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "release.apk"
            apk.write_bytes(b"synthetic APK")
            metadata = dict(release(), apkSha256=builder.sha256(apk))
            signed = f"Signer #1 certificate SHA-256 digest: {builder.APK_SIGNER}\nVerified using v2 scheme (APK Signature Scheme v2): true\n"
            manifest = "package: name='com.dailybeat.app' versionCode='38' versionName='4.3.4' platformBuildVersionName='16'"
            tools = {"apksigner": "apksigner", "aapt": "aapt"}
            with mock.patch.object(builder, "run", side_effect=[signed, manifest]):
                builder.verify_apk(apk, metadata, tools)
            invalid = (
                [signed.replace(builder.APK_SIGNER, "ab" * 32), manifest],
                [signed.replace(": true", ": false"), manifest],
                [signed, manifest.replace("com.dailybeat.app", "com.attacker.app")],
                [signed, manifest.replace("versionCode='38'", "versionCode='37'")],
                [signed, manifest.replace("versionName='4.3.4'", "versionName='4.3.3'")],
            )
            for output in invalid:
                with self.subTest(output=output), mock.patch.object(builder, "run", side_effect=output), self.assertRaises(builder.BuildError):
                    builder.verify_apk(apk, metadata, tools)

    def test_publication_allowlist_excludes_secrets_logs_wrong_apks_and_paths(self):
        apk = "com.dailybeat.app_38.apk"
        for path in ("config.yml", "release.keystore", "private.p12", ".env", "status/update.json",
                     "index.jar", "index.xml",
                     "build.log", "com.attacker.app_38.apk", "com.dailybeat.app_37.apk",
                     "../entry.jar", "/entry.jar", "icons/../config.yml", "icons\\secret.png"):
            with self.subTest(path=path):
                self.assertFalse(builder.public_path(path, apk))
        for path in (apk, "entry.jar", "index-v2.json", "index.html", "index.png",
                     "icons/icon.png", "icons-640/com.dailybeat.app.38.png",
                     "com.dailybeat.app/en-US/phoneScreenshots/1.png"):
            self.assertTrue(builder.public_path(path, apk), path)

    def test_generated_artwork_padding_is_allowed_only_for_sha256_base64_suffix(self):
        prefix = "com.dailybeat.app/en-US/"
        hashed = "icon_FVgddPTYjwob6SdyoxU13aTxepu1McDNR571ngPBoA0=.png"
        self.assertTrue(builder.public_path(prefix + hashed, "com.dailybeat.app_38.apk"))
        for name in ("icon_bad=.png", hashed.replace("=", "=="), hashed.replace("=", "=oops"),
                     "=secret.png", "config.yml", "icon_" + "a" * 42 + "=.png"):
            self.assertFalse(builder.public_path(prefix + name, "com.dailybeat.app_38.apk"), name)

    def test_public_copy_skips_fdroid_status_but_refuses_unexpected_files_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "repo"
            source.mkdir()
            (source / "entry.jar").write_bytes(b"index")
            (source / "status").mkdir()
            (source / "status/update.json").write_text('{"private":"tool details"}')
            (source / "index.jar").write_bytes(b"legacy unverified index")
            (source / "index.xml").write_text("legacy unverified index")
            destination = root / "public"
            builder.copy_public_repository(source, destination, "com.dailybeat.app_38.apk")
            self.assertEqual([p.name for p in destination.iterdir()], ["entry.jar"])
            (source / "keystore.p12").write_bytes(b"must remain private")
            with self.assertRaises(builder.BuildError) as caught:
                builder.copy_public_repository(source, root / "refused", "com.dailybeat.app_38.apk")
            self.assertIn('"keystore.p12"', str(caught.exception))
            self.assertNotIn("must remain private", str(caught.exception))
            self.assertFalse((root / "refused").exists())
            (source / "keystore.p12").unlink()
            (source / "icons").symlink_to(root, target_is_directory=True)
            with self.assertRaises(builder.BuildError):
                builder.copy_public_repository(source, root / "linked", "com.dailybeat.app_38.apk")

    def test_tool_errors_never_echo_subprocess_output(self):
        error = builder.subprocess.CalledProcessError(1, ["fdroid"], output="password=secret")
        with mock.patch.object(builder.subprocess, "run", side_effect=error), self.assertRaises(builder.BuildError) as caught:
            builder.run(["fdroid", "update"])
        self.assertNotIn("secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
