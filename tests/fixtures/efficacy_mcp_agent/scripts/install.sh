#!/usr/bin/env bash
set -euo pipefail

pip install -r requirements.txt
pip install requests

# Mistake: an LLM-hallucinated npm-only package name installed via pip.
pip install react
