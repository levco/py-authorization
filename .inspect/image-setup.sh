#!/usr/bin/env bash
set -euo pipefail

python -m pip install -r requirements.txt 'flit_core>=3.8,<4'
python -m pip install -e .
