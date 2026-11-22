# depguard

Lightweight Python dependency vulnerability scanner. Reads a `requirements.txt`,
queries the [OSV.dev](https://osv.dev) vulnerability database, and reports any
known vulnerabilities affecting your pinned packages. Exits non-zero when
vulnerabilities are found, so it fits directly into a CI pipeline.

stdlib only — no third-party dependencies.

## Why

Dependency vulnerabilities are a leading supply-chain risk. depguard is a tiny,
zero-dependency guardrail: point it at your requirements file and it tells you
which packages carry known advisories. It is intentionally small so it can be
vendored, audited, and run anywhere Python runs.

## Install

```bash
pip install depguard
```

Or run from source:

```bash
python depguard.py requirements.txt
```

## Usage

```bash
# Scan a requirements file
depguard requirements.txt

# Custom ecosystem
depguard --ecosystem PyPI requirements.txt

# Docker
docker run --rm -v $(pwd)/requirements.txt:/requirements.txt depguard /requirements.txt
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | No known vulnerabilities |
| 1    | Vulnerabilities found |
| 2    | Could not read the requirements file |

CI example (fail the build on vulnerable dependencies):

```yaml
- run: depguard requirements.txt
```

## Output example

```
depguard: found vulnerabilities in 1 package(s):
  requests: 1 advisory(ies)
    - GHSA-xxxx: requests vulnerable to ...
```

## Tests

```bash
python -m pytest tests/ -v
```

Tests use `unittest` with a mocked `urllib` — no network required.

## Security notes

- Only package names and versions are sent to OSV.dev. No source code, secrets,
  or private identifiers are transmitted.
- Unpinned packages are reported without version-specific matching (OSV returns
  all advisories for the package name).
- A 404 from OSV.dev (package not in the database) is treated as no findings.

## Limitations

- PyPI ecosystem only by default (configurable with `--ecosystem`).
- Requires network access to reach api.osv.dev.
- Exact-version (`==`) pins are matched; range specifiers (`>=`) are treated as
  unpinned.

## License

MIT
