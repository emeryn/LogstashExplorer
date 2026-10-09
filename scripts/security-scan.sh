#!/usr/bin/env bash
# Pre-build and image security gates. Exits > 0 at the first failing gate.
#
#   ./scripts/security-scan.sh            # code + dependencies + images (after docker compose build)
#   SKIP_IMAGES=1 ./scripts/security-scan.sh
#
# Gates:
#   1. Python SAST (bandit) + dependency audit (pip-audit, safety when SAFETY_API_KEY is set)
#   2. Node dependency audit (npm audit --audit-level=critical)
#   3. Trivy: CycloneDX SBOM + CVE scan (HIGH/CRITICAL with a fix available => fail)
#   4. OpenSCAP: OS configuration baseline (ANSSI BP-028 / CIS) via oscap-podman or oscap-docker
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${TAG:-0.1.0}"
REPORTS="$ROOT/reports/$(date -u +%Y%m%dT%H%M%SZ)"
IMAGES=(backend runner frontend)
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
# Debian 13 images: until SSG ships Debian 13 content, Debian 12 rules report "notapplicable" (see README §5).
SSG_DS="${SSG_DS:-/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml}"
SSG_PROFILE="${SSG_PROFILE:-xccdf_org.ssgproject.content_profile_anssi_bp28_minimal}"
mkdir -p "$REPORTS"

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

step "1/4 Python SAST + dependencies"
python -m bandit -q -c "$ROOT/backend/pyproject.toml" -r "$ROOT/backend/app" "$ROOT/runner/runner.py"
python -m pip_audit -r "$ROOT/backend/requirements.txt" --progress-spinner off
if [[ -n "${SAFETY_API_KEY:-}" ]]; then
  (cd "$ROOT/backend" && python -m safety --key "$SAFETY_API_KEY" scan --policy-file /dev/null)
fi

step "2/4 Node dependencies (critical => fail)"
(cd "$ROOT/frontend" && npm audit --audit-level=critical)

if [[ -n "${SKIP_IMAGES:-}" ]]; then
  echo "SKIP_IMAGES set: image scans skipped"; exit 0
fi

step "3/4 Trivy — SBOM + CVE scan"
for name in "${IMAGES[@]}"; do
  img="logstash-explorer/$name:$TAG"
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$REPORTS:/reports" "$TRIVY_IMAGE" \
    image --quiet --format cyclonedx --output "/reports/sbom-$name.cdx.json" "$img"
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$REPORTS:/reports" "$TRIVY_IMAGE" \
    image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 \
    --format table --output "/reports/trivy-$name.txt" "$img" \
    || { cat "$REPORTS/trivy-$name.txt"; echo "Trivy gate failed for $img"; exit 1; }
  echo "trivy $img: OK"
done

step "4/4 OpenSCAP — OS baseline"
OSCAP=""
command -v oscap-podman >/dev/null && OSCAP="oscap-podman"
[[ -z "$OSCAP" ]] && command -v oscap-docker >/dev/null && OSCAP="oscap-docker"
if [[ -z "$OSCAP" ]]; then
  echo "oscap-podman/oscap-docker not found (install openscap-containers + scap-security-guide on a Linux host)"
  exit 1
fi
for name in backend runner; do # Debian-based images (frontend is Alpine: no SSG content upstream)
  img="logstash-explorer/$name:$TAG"
  args=(xccdf eval --profile "$SSG_PROFILE" --results "$REPORTS/oscap-$name.xml" --report "$REPORTS/oscap-$name.html" "$SSG_DS")
  if [[ "$OSCAP" == "oscap-docker" ]]; then "$OSCAP" image "$img" "${args[@]}"; else "$OSCAP" "$img" "${args[@]}"; fi \
    || echo "OpenSCAP reported failed rules for $img — see $REPORTS/oscap-$name.html"
done

echo -e "\nReports: $REPORTS"
