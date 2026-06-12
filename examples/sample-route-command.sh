#!/usr/bin/env bash
set -euo pipefail

python3 scripts/route_work.py \
  --json \
  --external-ok \
  --share-boundary redacted-packet \
  --requested-role security \
  --file-path scripts/build_contractor_packet.py \
  "Security review redacted packet behavior, audit logging, and contractor acceptance scoring."

python3 scripts/route_work.py \
  --json \
  --external-ok \
  --allow-disclosure-escalation \
  --share-boundary patch-branch \
  --requested-role web-design \
  --file-path docs/index.html \
  --file-path docs/styles.css \
  "Gemini web-design review for a public GitHub Pages refresh."
