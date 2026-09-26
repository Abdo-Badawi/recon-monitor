#!/usr/bin/env bash
# Install / check external recon tools (best-effort; missing tools are OK).
set -u
for t in subfinder amass findomain assetfinder dnsx puredns naabu httpx nuclei katana gau waybackurls ffuf gobuster dirsearch semgrep; do
  if command -v "$t" >/dev/null 2>&1; then echo "OK $t"; else echo "MISSING $t"; fi
done
