#!/bin/sh
# run_batteries.sh — the single-command fail-closed CDP battery runner.
#
# WHY: the two browser witnesses below are committed but UNREFERENCED — no
# cargo test invokes them and nothing points a fresh reader at them (the
# 2026-11-10 wiring gap: git grep test_failclosed_driver == 1 hit, itself).
# This runner is the entry point: it exists so "re-verify the pin" is
# runnable from a fresh clone with one command.
#
# USAGE (from anywhere; paths resolve from this file's location):
#   sh fixtures/single_file/run_batteries.sh
#
# RECIPE (the corrected witness recipe, supersedes the fabricated .sh names
# of the 07:14Z DM — cdp_failclosed_regression.sh / system_health_browser_
# gate.sh never existed):
#   node fixtures/single_file/test_failclosed_driver.js   # the T-D witness:
#     # fail-closed row doctrine on real painted verdicts (overclaim/
#     # underclaim/correct-declaration/--permissive/T-E tier arms)
#   node fixtures/single_file/run_fixture_gate.js         # the pivot gate:
#     # static all-pending + zero network, fixture pass required rows
#     # PROVEN, identity_link NOT PROVEN (ruling iii), self-measure of the
#     # shipped artifact vs the combiner pin
#
# REQUIREMENTS: node + google-chrome (default /usr/bin/google-chrome; the
# driver takes --chrome, the batteries do not override it). ~3 min total.
#
# EXIT: 0 iff BOTH witnesses pass. Any failure exits nonzero WITH the
# failing script's output visible (fail-closed doctrine: a missing chrome
# is a loud failure, never a skip).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
if ! command -v node >/dev/null 2>&1; then
  echo "run_batteries: node not found — FAIL, not skip" >&2
  exit 1
fi
if [ ! -x /usr/bin/google-chrome ] && ! command -v google-chrome >/dev/null 2>&1; then
  echo "run_batteries: google-chrome not found — FAIL, not skip" >&2
  exit 1
fi
echo "== [1/2] the T-D fail-closed witness =="
node "$HERE/test_failclosed_driver.js"
echo "== [2/2] the single-file fixture gate =="
node "$HERE/run_fixture_gate.js"
echo "ALL BATTERIES PASS"
