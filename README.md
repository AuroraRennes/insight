# Insight: Multi-level CoreSight decoder and verifier

[![GithubActions](https://github.com/qducasse/insight/actions/workflows/github-actions.yml/badge.svg)](https://github.com/QDucasse/insight/actions)

---

**Insight** is a multi-level decoder and verifier for ARM CoreSight. It parses raw CoreSigth packets, or the different results of `perf` outputs (that use [OpenCSD](https://github.com/Linaro/OpenCSD)). A set of verifiers are applied on the execution trace offline, such as a shadow stack or direct jump checker. The objective of this project is for it to serve as a blueprint for hardware decoding and verification later on.


## Installation


The project was developed using [`pipenv`](https://github.com/pypa/pipenv) and Python 3.9. whose installation is presented below as well:

- *`pyenv` installation:*
```bash
# Install required library headers for pyenv
sudo apt-get install build-essential zlib1g-dev libffi-dev libssl-dev libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev

# Install pyenv to manage Python versions
curl https://pyenv.run | bash

# Update PATH (append these to ~/.bashrc)
export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

- *`pipenv` installation:*
```bash
# Install pip
sudo apt-get install python3-pip

# Install pipenv
pip install --user pipenv

# Update PATH (append these to ~/.bashrc)
export PIPENV_BIN="$HOME/.local/bin"
command -v pipenv >/dev/null || export PATH="$PIPENV_BIN:$PATH"
```

- *`insight` installation:*
```bash
# Install gigue and its pipenv environment
git clone git@github.com:QDucasse/insight.git
pipenv install
pipenv shell
```

