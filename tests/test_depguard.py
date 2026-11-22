"""Tests for depguard (stdlib only).

urllib.request.urlopen is mocked so no network is required.
"""

from __future__ import annotations

import json
import unittest
import urllib.error
from unittest import mock

import depguard


class _FakeResponse:
    """Context-manager fake for urllib.request.urlopen."""

    def __init__(self, payload, status=200, reason="OK"):
        self._payload = payload
        self.status = status
        self.reason = reason

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ParseRequirementsTests(unittest.TestCase):
    def test_skips_blanks_and_comments(self):
        with mock.patch(
            "builtins.open",
            mock.mock_open(read_data="# comment\n\nrequests==2.28.0\n"),
        ):
            result = depguard.parse_requirements("requirements.txt")
        self.assertEqual(result, [("requests", "2.28.0")])

    def test_normalizes_names(self):
        with mock.patch(
            "builtins.open",
            mock.mock_open(read_data="My_Package==1.0\nOther_Pkg>=2.0\n"),
        ):
            result = depguard.parse_requirements("requirements.txt")
        self.assertEqual(result, [("my-package", "1.0"), ("other-pkg", None)])

    def test_handles_extras_and_markers(self):
        with mock.patch(
            "builtins.open",
            mock.mock_open(read_data="requests[security]==2.0; python_version<'3'\n"),
        ):
            result = depguard.parse_requirements("requirements.txt")
        self.assertEqual(result, [("requests", "2.0")])


class QueryOsvTests(unittest.TestCase):
    def test_returns_vulns(self):
        payload = {"vulns": [{"id": "GHSA-x", "summary": "bad stuff"}]}
        with mock.patch(
            "depguard.urllib.request.urlopen", return_value=_FakeResponse(payload)
        ) as m:
            result = depguard.query_osv("requests", "2.28.0")
        self.assertEqual(result, payload["vulns"])
        sent = json.loads(m.call_args.args[0].data.decode())
        self.assertEqual(sent["package"]["name"], "requests")
        self.assertEqual(sent["version"], "2.28.0")
        self.assertEqual(m.call_args.args[0].method, "POST")

    def test_omits_version_when_unpinned(self):
        with mock.patch(
            "depguard.urllib.request.urlopen", return_value=_FakeResponse({"vulns": []})
        ) as m:
            depguard.query_osv("requests", None)
        sent = json.loads(m.call_args.args[0].data.decode())
        self.assertNotIn("version", sent)

    def test_404_means_no_vulns(self):
        error = urllib.error.HTTPError(
            "https://api.osv.dev/v1/query", 404, "Not Found", {}, None
        )
        with mock.patch(
            "depguard.urllib.request.urlopen", side_effect=error
        ):
            result = depguard.query_osv("nonexistent-pkg", "1.0")
        self.assertEqual(result, [])


class ScanTests(unittest.TestCase):
    def test_returns_empty_when_no_vulns(self):
        with mock.patch(
            "depguard.urllib.request.urlopen", return_value=_FakeResponse({"vulns": []})
        ):
            result = depguard.scan([("requests", "2.28.0")])
        self.assertEqual(result, {})

    def test_collects_findings(self):
        def fake_open(req, timeout=20):
            body = json.loads(req.data.decode())
            name = body["package"]["name"]
            if name == "requests":
                return _FakeResponse(
                    {"vulns": [{"id": "GHSA-x", "summary": "summary"}]}
                )
            return _FakeResponse({"vulns": []})

        with mock.patch("depguard.urllib.request.urlopen", side_effect=fake_open):
            result = depguard.scan([("requests", "2.28.0"), ("jinja2", "3.0")])
        self.assertEqual(set(result), {"requests"})
        self.assertEqual(result["requests"][0]["id"], "GHSA-x")


class MainTests(unittest.TestCase):
    def _write(self, content):
        m = mock.mock_open(read_data=content)
        with mock.patch("builtins.open", m):
            with mock.patch(
                "depguard.urllib.request.urlopen",
                return_value=_FakeResponse({"vulns": []}),
            ):
                return depguard.main(["-"])

    def test_exit_zero_when_clean(self):
        # "-" is not a real path; parse_requirements would fail. Use a real file.
        with mock.patch(
            "builtins.open", mock.mock_open(read_data="requests==2.28.0\n")
        ):
            with mock.patch(
                "depguard.urllib.request.urlopen",
                return_value=_FakeResponse({"vulns": []}),
            ):
                code = depguard.main(["requirements.txt"])
        self.assertEqual(code, 0)

    def test_exit_nonzero_when_vulns(self):
        with mock.patch(
            "builtins.open", mock.mock_open(read_data="requests==2.28.0\n")
        ):
            with mock.patch(
                "depguard.urllib.request.urlopen",
                return_value=_FakeResponse(
                    {"vulns": [{"id": "GHSA-x", "summary": "s"}]}
                ),
            ):
                code = depguard.main(["requirements.txt"])
        self.assertEqual(code, 1)

    def test_exit_error_when_unreadable(self):
        code = depguard.main(["/nonexistent/requirements.txt"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
