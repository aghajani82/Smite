#!/usr/bin/env bash
# Branch-scoped GHCR trial digest signature. NOT a production release signature.
set -euo pipefail
hold() { echo "HOLD: unified trial image signature denied" >&2; exit 2; }

: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_REPOSITORY_OWNER:?}"
: "${GITHUB_REF:?}"
: "${GITHUB_SHA:?}"
: "${SMITE_IMAGE_ROLE:?}"
: "${SMITE_IMAGE_DIGEST:?}"

[[ "$GITHUB_REPOSITORY" == "aghajani82/Smite" ]] || hold
[[ "$GITHUB_REPOSITORY_OWNER" == "aghajani82" ]] || hold
[[ "${GITHUB_EVENT_NAME:-}" == "push" ]] || hold
[[ "${GITHUB_ACTOR:-}" == "aghajani82" ]] || hold
[[ "$GITHUB_REF" == "refs/heads/trial/unified-smite-install" ]] || hold
[[ "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ ]] || hold
[[ "$SMITE_IMAGE_ROLE" == "panel" || "$SMITE_IMAGE_ROLE" == "node" ]] || hold
[[ "$SMITE_IMAGE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || hold
command -v cosign >/dev/null 2>&1 || hold

image="ghcr.io/aghajani82/smite-${SMITE_IMAGE_ROLE}@${SMITE_IMAGE_DIGEST}"
identity="https://github.com/aghajani82/Smite/.github/workflows/unified-install-signed-trial.yml@refs/heads/trial/unified-smite-install"
issuer="https://token.actions.githubusercontent.com"

cosign sign --yes \
  -a "smite_source_sha=${GITHUB_SHA}" \
  -a "smite_role=${SMITE_IMAGE_ROLE}" \
  -a "smite_trial=unified-install" \
  "$image"
cosign verify \
  --certificate-identity="$identity" \
  --certificate-oidc-issuer="$issuer" \
  --certificate-github-workflow-repository="aghajani82/Smite" \
  --certificate-github-workflow-trigger="push" \
  --certificate-github-workflow-sha="$GITHUB_SHA" \
  -a "smite_source_sha=${GITHUB_SHA}" \
  -a "smite_role=${SMITE_IMAGE_ROLE}" \
  -a "smite_trial=unified-install" \
  "$image" >/dev/null

echo "UNIFIED_TRIAL_SIGNED_DIGEST_VERIFIED=${SMITE_IMAGE_ROLE}"
echo "MAIN_RELEASE_APPROVED=NO"
echo "HOST_ACTIVATION_AUTHORIZED=NO"
