"""Regression tests for extract.refang (stdlib unittest, no dependencies).

Run from the repo root:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

import analyze  # noqa: E402
import extract  # noqa: E402


class RefangSchemeTests(unittest.TestCase):
    def test_hxxps_keeps_the_s(self):
        self.assertEqual(extract.refang("hxxps://evil[.]top/x"), "https://evil.top/x")

    def test_hxxp_stays_http(self):
        self.assertEqual(extract.refang("hxxp://evil[.]top/x"), "http://evil.top/x")

    def test_case_insensitive(self):
        self.assertEqual(extract.refang("HXXPS://evil[.]top"), "https://evil.top")
        self.assertEqual(extract.refang("Hxxp://evil[.]top"), "http://evil.top")

    def test_ftp_variants(self):
        self.assertEqual(extract.refang("fxp://h[.]top"), "ftp://h.top")
        self.assertEqual(extract.refang("fxps://h[.]top"), "ftps://h.top")

    def test_word_boundary_respected(self):
        # "hxxp" inside another word must not be rewritten.
        self.assertEqual(extract.refang("nothxxps://x"), "nothxxps://x")


class RefangPipelineTests(unittest.TestCase):
    def test_defanged_https_does_not_trigger_plain_http(self):
        url = extract.urls_from_text(extract.refang("hxxps://bit[.]ly/3xYzAbq"))[0]
        self.assertTrue(url.startswith("https://"))
        codes = [s["code"] for s in analyze.analyze_url(url)["signals"]]
        self.assertNotIn("plain_http", codes)

    def test_defanged_http_still_triggers_plain_http(self):
        url = extract.urls_from_text(extract.refang("hxxp://bit[.]ly/3xYzAbq"))[0]
        codes = [s["code"] for s in analyze.analyze_url(url)["signals"]]
        self.assertIn("plain_http", codes)


if __name__ == "__main__":
    unittest.main()
