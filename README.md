# Insight: Multi-level CoreSight decoder and verifier

[![GithubActions](https://github.com/qducasse/insight/actions/workflows/github-actions.yml/badge.svg)](https://github.com/QDucasse/insight/actions)

---

**Insight** is a multi-level decoder and verifier for ARM CoreSight. It parses raw CoreSigth packets, or the different results of `perf` outputs (that use [OpenCSD](https://github.com/Linaro/OpenCSD)). A set of verifiers are applied on the execution trace offline, such as a shadow stack or direct jump checker. The objective of this project is for it to serve as a blueprint for hardware decoding and verification later on.


## Installation


The project uses [`uv`](https://docs.astral.sh/uv/) and Python 3.13 (uv fetches it if needed):

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install insight and its environment (dependencies pinned in uv.lock)
git clone git@github.com:QDucasse/insight.git
cd insight
uv sync

# Tests
uv run pytest

# Lint, format and type checks (as in CI; drop --check to reformat)
uv run ruff check
uv run ruff format --check
uv run mypy .
```

