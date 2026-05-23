# Deploying 0.5.0 to pleme-dev — full private ship

Targets **pleme-dev** in the **akeyless-development** AWS account.
Full end-to-end private path: laptop `nix build` → `kubectl
port-forward` → in-cluster Zot → flux reconciles. Nothing transits a
third-party registry. Cloudflare Edge is not in the push path.

Two binaries to push (pleme-io substrate at 0.5.0):
1. `engenho-promessa` — the 5-reconciler controller (D1 reconciler-engine,
   D2 validation-store, D5 scanner-catalog, D6 action_dispatcher
   persistence)
2. `validation-api` — REST + GraphQL + WebSocket + gRPC + MCP +
   complete OpenAPI spec for SDK gen

Nine Akeyless service images (akeyless-nix-images):
- `auth`, `uam`, `kfm`, `gator`, `bis`, `logan`, `mark`, `sdr`, `gateway`

## Standing rules (preserved across every step)

- `gameWardenForwarding.enabled` = `false` (no flow to Second Front)
- HarborMirror Reconciler ships dormant (defense in depth)
- Akeyless-source binaries Zot-only — never ghcr.io / Docker Hub
- Laptop push via `kubectl port-forward`, no Cloudflare Edge

## Prerequisites (one-time)

```sh
# 1. kubectl reaches pleme-dev
kubectl --context=pleme-dev -n zot-system get svc zot
# expect: ClusterIP on port 5000

# 2. age key for SOPS
ls ~/.config/sops/age/keys.txt

# 3. zot-pull-secret.sops.yaml encrypted (one-time per cluster)
# Follow the recipe in the header of
#   pleme-io/k8s/clusters/pleme-dev/apps/akeyless-validation/zot-pull-secret.sops.yaml
```

## Step 1 — Push pleme-io substrate binaries (0.5.0)

```sh
cd ~/code/github/pleme-io/engenho-promessa-controllers
nix develop -c scripts/private-push.sh \
    --kube-context pleme-dev \
    --tag 0.5.0 \
    engenho-promessa validation-api
```

What it does:
1. `kubectl -n zot-system port-forward svc/zot 5000:5000` (background)
2. Decrypts the akeyless-builder token from SOPS
3. `skopeo login --tls-verify=false localhost:5000 -u akeyless-builder`
4. For each binary: `nix build .#"image:<binary>"` → `skopeo copy` to
   `localhost:5000/pleme-io/<binary>:0.5.0` → `cosign sign --keyless`
   (Rekor upload OFF — we don't publish to public transparency log)
5. Tears down port-forward

## Step 2 — Push Akeyless service images

```sh
cd ~/code/github/akeylesslabs/akeyless-nix-images
nix develop -c scripts/private-push.sh \
    --kube-context pleme-dev
    # add `--no-cosign` to skip signing when iterating
```

Loops through all 9 services (`auth uam kfm gator bis logan mark sdr
gateway`). Each builds via `nix build .#"dockerImage:<svc>"`, then
skopeo copies via the same port-forward to
`localhost:5000/akeyless-<svc>:<tag>`. The tag is whatever the nix
build baked in (typically `latest` or the git short SHA — see
`lib/mk-akeyless-go-service.nix`).

Subset push:
```sh
scripts/private-push.sh auth uam       # just two
PRIVATE_PUSH_TAG_OVERRIDE=v1.2.3 scripts/private-push.sh auth
```

> **Reusable-pattern note (FOLLOWUP D-OP-9):** This script and
> `pleme-io/engenho-promessa-controllers/scripts/private-push.sh`
> share the same port-forward + skopeo + cosign shape. Extract to a
> single `substrate/lib/private-push.sh` so future consumers
> (kenshi BuildPipeline, ami-forge, etc.) import one canonical
> implementation instead of copying.

## Step 3 — Bump pleme-io/k8s helmrelease (if tag changed)

The 0.5.0 helmrelease has already been pushed. If you ever push at
a new tag, edit `clusters/pleme-dev/apps/akeyless-validation/
helmrelease.yaml` and bump `controller.image.tag` +
`api.image.tag`. Flux picks up within 10 min.

## Step 4 — Verify everything

```sh
# Substrate pods rolling new image
kubectl --context=pleme-dev -n akeyless-validation describe pod \
    -l app.kubernetes.io/component=controller | grep -E "Image:|Image ID:"
# expect: Image: zot.zot-system.svc.cluster.local:5000/pleme-io/engenho-promessa:0.5.0

kubectl --context=pleme-dev -n akeyless-validation describe pod \
    -l app.kubernetes.io/component=api | grep -E "Image:"
# expect: zot.zot-system.svc.cluster.local:5000/pleme-io/validation-api:0.5.0

# Controller booted the validation-store + spawned 5 reconcilers
kubectl --context=pleme-dev -n akeyless-validation logs \
    deploy/akeyless-validation-controller | \
    grep -E "validation-store schema ensured|reconciler|action_dispatcher"

# API serving everything
kubectl --context=pleme-dev -n akeyless-validation port-forward \
    svc/akeyless-validation-api 8080:8080 50051:50051 &

# REST
curl -s http://localhost:8080/v1/scanners | jq '.[].kind' | head -5
curl -s http://localhost:8080/v1/compliance-summary | jq

# OpenAPI spec (SDK-gen ready)
curl -s http://localhost:8080/v1/openapi.json | jq '.info.version, .paths | keys | length'
# expect: "0.5.0", 18

# gRPC (tonic-reflection)
grpcurl -plaintext localhost:50051 list
# expect:
#   grpc.reflection.v1.ServerReflection
#   validation.v1.ComplianceService
#   validation.v1.ScannerCatalogService
#   validation.v1.ValidationService

# Scanner catalog over gRPC
grpcurl -plaintext localhost:50051 \
    validation.v1.ScannerCatalogService/ListScanners | jq '.items[].kind'

# Akeyless service images present in Zot
kubectl --context=pleme-dev -n zot-system port-forward svc/zot 5000:5000 &
curl -s -u akeyless-builder:$TOKEN \
    http://localhost:5000/v2/_catalog | jq
# expect: { "repositories": ["akeyless-auth", "akeyless-uam", ...] }
```

## Step 5 — Generate SDKs from the OpenAPI spec

```sh
curl -s http://localhost:8080/v1/openapi.json > /tmp/spec.json

# TypeScript
openapi-generator generate -i /tmp/spec.json -g typescript-axios -o ~/sdk-ts

# Rust
openapi-generator generate -i /tmp/spec.json -g rust -o ~/sdk-rust

# Python
openapi-generator generate -i /tmp/spec.json -g python -o ~/sdk-py
```

The same is doable via gRPC for typed protocol clients:

```sh
mkdir -p ~/sdk-grpc
protoc -I ~/code/github/pleme-io/engenho-promessa-controllers/validation-api/proto \
    --go_out=~/sdk-grpc --go-grpc_out=~/sdk-grpc \
    ~/code/github/pleme-io/engenho-promessa-controllers/validation-api/proto/validation.proto
```

## Rollback

```sh
cd ~/code/github/pleme-io/k8s
git revert <commit-bumping-helmrelease>
git push
# Flux rolls the deployment back. PVC keeps its data; no manual cleanup.
```

## What runs in the cluster after this

```
namespace akeyless-validation/
├── deploy/akeyless-validation-controller (1 replica + PVC)
│   ├── engenho-promessa binary
│   │   ├── 5 reconcilers (image_validation / ephemeral_tenant /
│   │   │   scan_job / outcome_chain / action_dispatcher)
│   │   ├── validation-store on SQLite at /var/lib/validation-store
│   │   └── spawns Job per ScannerKind via scanner-catalog
│   │       (Trivy + Grype + Syft + Trufflehog + Semgrep + KubeLinter
│   │       + kube-bench + kube-hunter + Polaris + StigCisValidator
│   │       + ZAP = 11 OSS scanners default-on)
│   └── PVC akeyless-validation-store (5Gi RWO)
├── deploy/akeyless-validation-api (2 replicas)
│   ├── HTTP :8080 — REST / GraphQL / WS / OpenAPI / metrics
│   └── gRPC :50051 — validation.v1.{Validation,ScannerCatalog,
│                     Compliance}Service + tonic-reflection
└── 3 CRDs (validation.pleme.io/v1)
    ├── AkeylessImageValidation
    ├── AkeylessEphemeralTenant
    └── ScanJob
```

Image source for every workload above: `zot.zot-system.svc.cluster.local:5000/*`
— private cluster-internal Zot. No third-party plane.
