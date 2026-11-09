# Insight: Multi-level CoreSight decoder and verifier

[![GithubActions](https://github.com/qducasse/insight/actions/workflows/github-actions.yml/badge.svg)](https://github.com/QDucasse/insight/actions)

---

**Insight** is a multi-level decoder and verifier for ARM CoreSight. It decodes raw CoreSight packets (ETM, STM) and checks the tag-tracking annotations the HBNG compiler embeds in a binary. The objective of this project is for it to serve as a blueprint for hardware decoding and verification later on.

The `perf`-based parsers and control-flow verifiers (shadow stack, direct jumps) are on the `legacy` branch.


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

