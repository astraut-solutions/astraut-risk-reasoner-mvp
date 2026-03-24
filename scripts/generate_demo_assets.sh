#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="docs/demo"
mkdir -p "${OUT_DIR}"

record_and_render() {
  local name="$1"
  local cmd="$2"
  local cast="${OUT_DIR}/${name}.cast"
  local gif="${OUT_DIR}/${name}.gif"

  asciinema rec \
    --quiet \
    --overwrite \
    --idle-time-limit 1 \
    --command "${cmd}" \
    "${cast}"

  agg \
    --speed 1.15 \
    --cols 110 \
    --rows 34 \
    "${cast}" \
    "${gif}"
}

record_and_render "demo" "astraut-risk demo"
record_and_render "checklist" "astraut-risk checklist"
record_and_render "matrix" "astraut-risk matrix"

# Keep a stable default artifact name for README embedding if desired.
cp "${OUT_DIR}/demo.gif" "${OUT_DIR}/latest.gif"
