"""depguard - lightweight Python dependency vulnerability scanner.

Reads a requirements.txt, queries the OSV.dev vulnerability database for each
package, and reports affected versions. Exits non-zero when vulnerabilities are
found so it can fail a CI pipeline.

stdlib only: urllib, argparse, json, sys, re.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Iterable

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
EXIT_OK = 0
EXIT_VULNS = 1
EXIT_ERROR = 2

_PACKAGE_NAME_NORMALIZE = re.compile(r"[-_.]+")


def normalize_name(name: str) -> str:
    """PyPI-style normalization: lowercase, runs of - _ . collapsed to one -."""
    return _PACKAGE_NAME_NORMALIZE.sub("-", name.strip()).lower()


_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")


def parse_requirements(path: str) -> list[tuple[str, str | None]]:
    """Parse a requirements.txt into (name, version) pairs.

    Skips blank lines, comments, and pip options (-r, --hash, ...). Only an
    exact pin (==) yields a version OSV can match; range specifiers are treated
    as unpinned because the installed version is unknown.
    """
    requirements: list[tuple[str, str | None]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            name_part = line.split(";")[0].strip()
            match = _NAME_RE.match(name_part)
            if not match:
                continue
            name = normalize_name(match.group(0))  # drops extras like [security]
            version = None
            if "==" in name_part:
                _, _, version = name_part.partition("==")
                version = version.strip() or None
            if name:
                requirements.append((name, version))
    return requirements


def query_osv(name: str, version: str | None, ecosystem: str = "PyPI") -> list[dict]:
    """Query OSV.dev for vulnerabilities affecting a package version."""
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []  # package not in the database
        raise
    return body.get("vulns", [])


def scan(
    requirements: Iterable[tuple[str, str | None]],
    ecosystem: str = "PyPI",
) -> dict[str, list[dict]]:
    """Return {package: [vulns]} for every requirement with findings."""
    findings: dict[str, list[dict]] = {}
    for name, version in requirements:
        vulns = query_osv(name, version, ecosystem)
        if vulns:
            findings[name] = vulns
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="depguard",
        description="Scan a Python requirements file for known vulnerabilities (OSV.dev).",
    )
    parser.add_argument("requirements", help="Path to requirements.txt")
    parser.add_argument(
        "--ecosystem",
        default="PyPI",
        help="Package ecosystem (default: PyPI)",
    )
    args = parser.parse_args(argv)

    try:
        requirements = parse_requirements(args.requirements)
    except OSError as exc:
        print(f"depguard: cannot read {args.requirements}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        findings = scan(requirements, args.ecosystem)
    except OSError as exc:
        print(f"depguard: cannot reach OSV.dev: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not findings:
        print(f"depguard: no known vulnerabilities in {len(requirements)} package(s).")
        return EXIT_OK

    print(f"depguard: found vulnerabilities in {len(findings)} package(s):")
    for name, vulns in findings.items():
        print(f"  {name}: {len(vulns)} advisory(ies)")
        for vuln in vulns:
            vid = vuln.get("id", "?")
            summary = vuln.get("summary", "no summary")
            print(f"    - {vid}: {summary}")
    return EXIT_VULNS


if __name__ == "__main__":
    sys.exit(main())
