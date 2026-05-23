#!/usr/bin/env bash
# private-push.sh — laptop → in-cluster Zot, bypassing Cloudflare Edge.
#
# ────────────────────────────────────────────────────────────────────
# DEPRECATED: shell. Replaced by a typed Rust binary next session
# (FOLLOWUP D-OP-9 / NEXT). User directive 2026-05-22: "shell
# scripting you can throw away for rust/tatara-lisp". This script
# stays operational until the Rust `private-push` workspace member
# lands.
# ────────────────────────────────────────────────────────────────────
#
# Standing rule (memory feedback_akeyless_image_privacy.md):
# Akeyless-source-processing binaries (engenho-promessa,
# validation-api) NEVER touch a third-party registry. The push
# path is:
#
#   laptop ── kubectl port-forward ──► in-cluster Zot Service ──► lacre admit ──► Zot blob store
#
# kubectl port-forward keeps the bytes inside the cluster network past
# the EKS / k3s control-plane endpoint. No Cloudflare Edge in the
# path, no third-party registry (ghcr.io / Docker Hub / etc.).
#
# What runs:
#   1. `kubectl port-forward -n zot-system svc/zot 5000:5000` (background)
#   2. Wait for the local port to accept connections
#   3. Decrypt the akeyless-builder token from SOPS
#   4. `skopeo login localhost:5000 --tls-verify=false`
#   5. For each binary requested:
#      a. `nix build .#"image:<binary>"`
#      b. `skopeo copy docker-archive:./result docker://localhost:5000/pleme-io/<binary>:<tag>`
#      c. `cosign sign --yes --tlog-upload=false <ref-by-digest>`
#         (Keyless via OIDC interactive — Sigstore Fulcio short-cert.
#          --tlog-upload=false because Rekor is public; keep our
#          signatures private until D-OP-9 deploys an internal Rekor
#          or we explicitly opt into public transparency.)
#   6. Tear down the port-forward
#
# Usage:
#   scripts/private-push.sh engenho-promessa validation-api
#   scripts/private-push.sh engenho-promessa --tag 0.2.0
#   scripts/private-push.sh --kube-context pleme-dev engenho-promessa
#
# Env overrides:
#   PRIVATE_PUSH_TAG       (default: 0.2.0)
#   PRIVATE_PUSH_REPO      (default: pleme-io)
#   PRIVATE_PUSH_K8S_NS    (default: zot-system)
#   PRIVATE_PUSH_SVC       (default: zot)
#   PRIVATE_PUSH_PORT      (default: 5000)
#   PRIVATE_PUSH_TOKEN_PATH (default: ~/code/github/pleme-io/k8s/clusters/pleme-dev/infrastructure/zot-stack/zot/zot-push-token.sops.yaml)
#   PRIVATE_PUSH_SKIP_COSIGN=1  to skip the signing step (dev/iterating only)

set -euo pipefail

TAG="${PRIVATE_PUSH_TAG:-0.2.0}"
REPO_PREFIX="${PRIVATE_PUSH_REPO:-pleme-io}"
NS="${PRIVATE_PUSH_K8S_NS:-zot-system}"
SVC="${PRIVATE_PUSH_SVC:-zot}"
PORT="${PRIVATE_PUSH_PORT:-5000}"
TOKEN_PATH="${PRIVATE_PUSH_TOKEN_PATH:-$HOME/code/github/pleme-io/k8s/clusters/pleme-dev/infrastructure/zot-stack/zot/zot-push-token.sops.yaml}"
KUBE_CONTEXT=""
BINARIES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --repo) REPO_PREFIX="$2"; shift 2 ;;
        --kube-context) KUBE_CONTEXT="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        *) BINARIES+=("$1"); shift ;;
    esac
done

if [[ ${#BINARIES[@]} -eq 0 ]]; then
    echo "fatal: specify at least one binary (engenho-promessa, validation-api)" >&2
    exit 1
fi

KUBECTL="kubectl"
[[ -n "$KUBE_CONTEXT" ]] && KUBECTL="kubectl --context=$KUBE_CONTEXT"

# Sanity: kubectl can reach the cluster + the Zot Service exists.
$KUBECTL -n "$NS" get svc "$SVC" >/dev/null || {
    echo "fatal: cannot find Service $NS/$SVC — is your kubeconfig pointed at pleme-dev?" >&2
    echo "      check: $KUBECTL config current-context" >&2
    exit 1
}

# Sanity: SOPS-encrypted token decrypts.
if [[ ! -f "$TOKEN_PATH" ]]; then
    echo "fatal: token path $TOKEN_PATH not found — override with PRIVATE_PUSH_TOKEN_PATH" >&2
    exit 1
fi
TOKEN=$(sops -d "$TOKEN_PATH" | yq -r '.data.token' | base64 -d)
if [[ -z "$TOKEN" ]]; then
    echo "fatal: decrypted token is empty (sops error?)" >&2
    exit 1
fi

# Start kubectl port-forward in the background; the trap kills it on
# exit (success or failure). Local port may already be in use; we let
# kubectl error and fail fast.
echo "[private-push] starting port-forward $NS/svc/$SVC :$PORT → localhost:$PORT …"
$KUBECTL -n "$NS" port-forward "svc/$SVC" "$PORT:$PORT" >/tmp/private-push-pf.log 2>&1 &
PF_PID=$!
trap 'kill $PF_PID 2>/dev/null || true; rm -f /tmp/private-push-pf.log' EXIT

# Wait for port to accept connections (max ~10s).
for _ in $(seq 1 50); do
    if (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        break
    fi
    sleep 0.2
done
if ! (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    echo "fatal: port-forward did not come up — /tmp/private-push-pf.log:" >&2
    cat /tmp/private-push-pf.log >&2
    exit 1
fi
echo "[private-push] port-forward up; logging into localhost:$PORT as akeyless-builder"

# skopeo login over localhost (loopback) with --tls-verify=false because
# in-cluster Zot speaks plain HTTP on the Service IP (TLS is terminated
# by nginx at the external ingress only).
skopeo login --tls-verify=false --username akeyless-builder --password "$TOKEN" "localhost:$PORT"

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

for BINARY in "${BINARIES[@]}"; do
    DEST="localhost:$PORT/$REPO_PREFIX/$BINARY:$TAG"
    echo "[private-push] [$BINARY] nix building image …"
    nix build ".#image:$BINARY" -o "result-$BINARY"
    IMG_PATH=$(readlink -f "result-$BINARY")

    echo "[private-push] [$BINARY] skopeo copy → $DEST"
    skopeo copy --dest-tls-verify=false \
        "docker-archive:$IMG_PATH" \
        "docker://$DEST"

    if [[ "${PRIVATE_PUSH_SKIP_COSIGN:-}" != "1" ]]; then
        echo "[private-push] [$BINARY] resolving pushed digest …"
        DIGEST=$(skopeo inspect --tls-verify=false "docker://$DEST" | yq -r '.Digest')
        REF_BY_DIGEST="localhost:$PORT/$REPO_PREFIX/$BINARY@$DIGEST"
        echo "[private-push] [$BINARY] cosign sign --keyless (Rekor upload off) → $REF_BY_DIGEST"
        cosign sign --yes --allow-insecure-registry --tlog-upload=false "$REF_BY_DIGEST"
    else
        echo "[private-push] [$BINARY] SKIP_COSIGN=1 — skipping signature"
    fi

    rm -f "result-$BINARY"
done

echo "[private-push] done. pulled in-cluster via:"
echo "  zot.zot-system.svc.cluster.local:$PORT/$REPO_PREFIX/<binary>:$TAG"
