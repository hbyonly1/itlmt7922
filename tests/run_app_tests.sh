#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause-Clear
set -eu
test_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 "$test_root/tests/test_app_state.py"
