# Deploying `engenho-promessa-controllers` 0.2.0 to pleme-dev

Targets the **pleme-dev cluster** in the **akeyless-development** AWS
account. This release ships D1 (reconciler-engine + action_dispatcher),
D2 (validation-store SeaORM persistence), and D6 (outcome persistence
wiring) on top of the existing M1.5 substrate.

The HarborMirror reconciler ships **dormant** — `gameWardenForwarding.enabled=false`
in the chart values. No images flow to Second Front until that flag
is intentionally flipped (a separate, two-PR maneuver per the D6
plan).

## Prerequisites (one-time, laptop)

1. **Cloudflare tunnel up.** If `curl -sI https://zot-dev.quero.cloud/v2/`
   returns Cloudflare error 1033, run the idempotent bootstrap:
   ```sh
   ~/code/github/pleme-io/k8s/clusters/pleme-dev/infrastructure/zot-tunnel/bootstrap-rio-zot-tunnel.tlisp
   ```
   Then commit + push the two staged diffs (in `pleme-io/nix` and
   `pleme-io/k8s`). Wait for nixos-rebuild on rio + flux reconcile on
   pleme-dev; verify with `curl -sI https://zot-dev.quero.cloud/v2/`
   → expect HTTP 401 (auth required), not 530.

2. **Zot push token decrypted.** The `akeyless-builder` API-key bot
   creds live SOPS-encrypted in the k8s repo:
   ```sh
   TOKEN=$(sops -d \
     ~/code/github/pleme-io/k8s/clusters/pleme-dev/infrastructure/zot-stack/zot/zot-push-token.sops.yaml \
     | yq '.data.token')
   skopeo login zot-dev.quero.cloud --username akeyless-builder --password "$TOKEN"
   ```

## Step 1 — Build the 0.2.0 OCI images locally

```sh
cd ~/code/github/pleme-io/engenho-promessa-controllers
nix build .#"image:engenho-promessa"
ENGENHO_IMG=$(readlink -f result)
nix build .#"image:validation-api"
API_IMG=$(readlink -f result)
```

Each output is a `dockerTools.buildLayeredImage` tarball — non-root
(UID 65532), tini PID 1, distroless-shaped.

> **FOLLOWUP (D-OP-9):** The current flake hand-inlines
> `dockerTools.buildLayeredImage`. The canonical substrate way is to
> import `substrate/lib/build/rust/tool-image-flake.nix` (see
> `pleme-io/image-sync/flake.nix:30-46` for the template). That gives
> a free multi-arch `apps.release` app driven by `forge image-release`,
> with `{arch}-{git-short-sha}` immutable tags. Out of scope for 0.2.0
> ship; do it before 0.3.0.

## Step 2 — Push privately to Zot

For now the helmrelease still points at `ghcr.io/pleme-io/...`. Two
publishing options:

### Option A — Push to `ghcr.io/pleme-io` (current default)

```sh
skopeo copy docker-archive:"$ENGENHO_IMG" docker://ghcr.io/pleme-io/engenho-promessa:0.2.0
skopeo copy docker-archive:"$API_IMG"     docker://ghcr.io/pleme-io/validation-api:0.2.0
```

ghcr `pleme-io` packages are org-internal — they require the
`ghcr-pull-secret` SOPS Secret that's already applied in the
`akeyless-validation` namespace.

### Option B — Push privately to the cluster-singleton Zot

Edit `helmrelease.yaml` repository fields to point at
`zot-dev.quero.cloud/pleme-io/...` first, then:

```sh
skopeo copy docker-archive:"$ENGENHO_IMG" docker://zot-dev.quero.cloud/pleme-io/engenho-promessa:0.2.0
skopeo copy docker-archive:"$API_IMG"     docker://zot-dev.quero.cloud/pleme-io/validation-api:0.2.0
```

This routes through **lacre** (the content-addressed gate in front
of Zot — pushes go through lacre's PUT interceptor which queries
cartorio before forwarding to Zot). Tighter than ghcr; matches the
"private clean-room registry" intent.

> Recommendation: stay on Option A for the 0.2.0 cut (helmrelease is
> already wired for it); move to Option B in the same PR as the
> substrate flake refactor.

## Step 3 — Bump pleme-io/k8s, push commits, watch flux reconcile

```sh
cd ~/code/github/pleme-io/k8s
git diff clusters/pleme-dev/apps/akeyless-validation/helmrelease.yaml
# Should show: tag 0.1.0 → 0.2.0 + new validationStore block

cd ~/code/github/pleme-io/helmworks-akeyless
git diff charts/lareira-akeyless-validation/
# Should show: Chart.yaml version bump, values.yaml store wiring,
# controller-deployment.yaml env + volumeMount, new pvc template

cd ~/code/github/pleme-io/engenho-promessa-controllers
git diff
# Should show: 0.1.0 → 0.2.0, validation-store dep, action_dispatcher
# persistence, engenho-promessa main DB init
```

Push all three to main. Flux on pleme-dev reconciles
`helmworks-akeyless` (5m GitRepository interval) and the
HelmRelease (10m interval) — picks up within ~2 min of push.

## Step 4 — Verify everything is up + working

```sh
# Flux picked up the new chart version
kubectl -n flux-system get gitrepository helmworks-akeyless
kubectl -n flux-system get helmrelease akeyless-validation
kubectl -n flux-system describe helmrelease akeyless-validation | tail -20

# PVC bound
kubectl -n akeyless-validation get pvc akeyless-validation-store
# expect: STATUS Bound, CAPACITY 5Gi

# Controller pod up with new image + env var
kubectl -n akeyless-validation get deploy akeyless-validation-controller
kubectl -n akeyless-validation describe pod -l app.kubernetes.io/component=controller | grep -E "Image:|VALIDATION_DB_URL"
# expect: Image: ghcr.io/pleme-io/engenho-promessa:0.2.0
#         VALIDATION_DB_URL: sqlite:///var/lib/validation-store/validation.db?mode=rwc

# API pod up with new image
kubectl -n akeyless-validation get deploy akeyless-validation-api
kubectl -n akeyless-validation describe pod -l app.kubernetes.io/component=api | grep Image:
# expect: Image: ghcr.io/pleme-io/validation-api:0.2.0

# Controller booted the store + ensured tables
kubectl -n akeyless-validation logs deploy/akeyless-validation-controller | grep -E "validation-store|reconciler"
# expect:
#   engenho-promessa — opening validation-store
#   validation-store schema ensured (idempotent)
#   engenho-promessa — booting validation-controllers (5 reconcilers)
#   action_dispatcher starting registered_kinds=...

# Five reconcilers spinning
kubectl -n akeyless-validation logs deploy/akeyless-validation-controller | grep -E "starting|OutcomeChainAppender"
# expect lines from image_validation, ephemeral_tenant, scan_job,
# outcome_chain, action_dispatcher

# CRDs present
kubectl get crd | grep validation.pleme.io
# expect: akeylessephemeraltenants, akeylessimagevalidations, scanjobs
```

## Step 5 — End-to-end smoke (when there's a real Akeyless digest)

Once Step 1 of the FedRAMP master plan is in place (vendor commit
on `akeyless-main-repo/nix-images-vendor` — already done — plus the
first `nix run .#"release:auth"` from the akeyless-nix-images repo
landing a real digest in Zot):

```sh
# A test AkeylessImageValidation CR walks the typed phase chain
kubectl -n akeyless-validation get akeylessimagevalidations -w
# expect transitions: Pending → Provisioning → Scanning → Aggregating
#                     → Attesting → Gating → Passed (or Failed)

# ScanJob children materialize per scanner
kubectl -n akeyless-validation get scanjobs

# The SecurityController emits a typed Decision; the action_dispatcher
# routes it through the reconciler-engine; the dispatch outcome
# lands in validation-store
kubectl -n akeyless-validation logs deploy/akeyless-validation-controller \
  | grep "action dispatched\|already-converged\|flag-gated"

# Inspect store rows (one row per AkeylessImageValidation
# observation + one row per reconciler dispatch)
kubectl -n akeyless-validation exec deploy/akeyless-validation-controller \
  -- sqlite3 /var/lib/validation-store/validation.db \
  "SELECT id, action_kind, reconciler_kind, outcome, gate_decision_decided_at \
   FROM reconciler_outcomes ORDER BY dispatched_at DESC LIMIT 20;"
```

## Rollback

If 0.2.0 misbehaves on pleme-dev:

```sh
cd ~/code/github/pleme-io/k8s
git revert <commit-bumping-helmrelease> # rolls tag 0.2.0 → 0.1.0
git push
```

The PVC keeps its data across rollback — no manual cleanup needed.
If you DO want to wipe the store:

```sh
kubectl -n akeyless-validation delete pvc akeyless-validation-store
# Flux will recreate on next reconcile + the controller pod rolls.
```

## The standing rule

`gameWardenForwarding.enabled` remains **`false`** at every step of
this deploy. The HarborMirror reconciler ships dormant (defense in
depth — both the SecurityController gate AND the Reconciler itself
re-check the flag). Flipping requires explicit intent + the D9
sekiban CompliancePolicy admission gate that's planned to land
before the flag flips to `true`.
