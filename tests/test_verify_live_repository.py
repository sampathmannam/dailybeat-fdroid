from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    import verify_live_repository as live
finally:
    sys.path.pop(0)


class VerifyLiveRepositoryTest(unittest.TestCase):
    def test_live_fetch_rejects_other_hosts_queries_and_paths_before_network(self):
        destination = Path("index-v1.jar")
        for url in ("https://attacker.example/index-v1.jar", live.builder.REPOSITORY_URL + "/../index-v1.jar",
                    live.builder.REPOSITORY_URL + "/index-v1.jar?token=anything", "file:///index-v1.jar"):
            with self.subTest(url=url), mock.patch.object(live.urllib.request, "build_opener") as opener:
                with self.assertRaises(live.builder.BuildError):
                    live.download_public(url, destination, 1024, 1000)
                opener.assert_not_called()

    def test_redirect_is_rejected_even_to_another_https_origin(self):
        with self.assertRaises(live.builder.BuildError):
            live.NoRedirects().redirect_request(None, None, 302, "Found", {}, "https://attacker.example/index-v1.jar")

    def test_index_archive_requires_one_reviewed_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "index-v1.jar"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", b"manifest")
                archive.writestr("index-v1.json", b"{}")
            live.check_index_archive(path, "index-v1.json")
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("unreviewed.json", b"{}")
            with self.assertRaises(live.builder.BuildError):
                live.check_index_archive(path, "index-v1.json")

    def test_compressed_index_expansion_is_bounded_before_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "entry.jar"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("entry.json", b"x" * (live.builder.MAX_JSON_BYTES + 1))
            self.assertLess(path.stat().st_size, 1024 * 1024)
            with self.assertRaises(live.builder.BuildError):
                live.check_index_archive(path, "entry.json")


if __name__ == "__main__":
    unittest.main()
