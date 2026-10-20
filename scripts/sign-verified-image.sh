#!/usr/bin/env bash
# Applied ONLY by the existing explicitly allowed GHCR publishing workflow.
# Never signs a tag or local Docker ID; signs the immutable registry digest.
set -euo pipefail

hold() { echo "HOLD: $*" >&2; exit 2; }

: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_REPOSITORY_OWNER:?}"
: "${GITHUB_REF:?}"
: "${GITHUB_SHA:?}"
: "${SMITE_IMAGE_ROLE:?}"
: "${SMITE_IMAGE_DIGEST:?}"

[[ "${GITHUB_REPOSITORY,,}" == "aghajani82/smite" ]] || hold "Unexpected repository"
[[ "${GITHUB_REPOSITORY_OWNER,,}" == "aghajani82" ]] || hold "Unexpected owner"
[[ "$GITHUB_REF" =~ ^refs/heads/(main|next|beta|tst)$ || "$GITHUB_REF" =~ ^refs/tags/v[0-9][a-zA-Z0-9._-]*$ ]] || hold "Unapproved publication ref"
[[ "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ ]] || hold "Source SHA must be immutable commit"
[[ "$SMITE_IMAGE_ROLE" == "panel" || "$SMITE_IMAGE_ROLE" == "node" ]] || hold "Invalid image role"
[[ "$SMITE_IMAGE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || hold "Missing immutable registry digest"
command -v cosign >/dev/null 2>&1 || hold "Cosign is not available"

image="ghcr.io/aghajani82/smite-${SMITE_IMAGE_ROLE}@${SMITE_IMAGE_DIGEST}"
identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/publish-images.yml@${GITHUB_REF}"
issuer="https://token.actions.githubusercontent.com"

# GitHub Actions OIDC certificate and the signed role/source assertions
# are verified against this exact immutable digest. No wildcard identity.
cosign sign --yes -a "smite_source_sha=${GITHUB_SHA}" -a "smite_role=${SMITE_IMAGE_ROLE}" "$image"
cosign verify \
  --certificate-identity="$identity" \
  --certificate-oidc-issuer="$issuer" \
  -a "smite_source_sha=${GITHUB_SHA}" \
  -a "smite_role=${SMITE_IMAGE_ROLE}" \
  "$image" >/dev/null

echo "SMITE_SIGNED_REGISTRY_DIGEST_VERIFIED=${SMITE_IMAGE_ROLE}"
echo "PAIR_ATTESTATION_AND_RELEASE_APPROVAL=NOT_PROVEN"
