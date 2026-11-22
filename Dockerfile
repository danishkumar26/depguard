# Dockerfile for depguard
# Build:  docker build -t depguard .
# Run:    docker run --rm -v $(pwd)/requirements.txt:/requirements.txt depguard /requirements.txt

FROM python:3.12-slim

WORKDIR /app

COPY depguard.py pyproject.toml README.md ./

RUN pip install --no-cache-dir -e . >/dev/null 2>&1 || true

ENTRYPOINT ["depguard"]
CMD ["--help"]
