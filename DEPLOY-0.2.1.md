# Deploying `engenho-promessa-controllers` 0.2.1 to pleme-dev — private path

Targets the **pleme-dev cluster** in the **akeyless-development** AWS
account. This deploy ships D1 (reconciler-engine + action_dispatcher),
D2 (validation-store), D6 (outcome persistence) **plus the standing
privacy rule** — Akeyless-source-processing binaries (engenho-promessa,
validation-api) NEVER touch a third-party registry. The push path:

```
operator laptop ── kubectl port-forward ──► in-cluster Zot Service ──► Zot blob store
                       (no Cloudflare Edge, no ghcr.io, no public registry)
                                              │
                                              └── cosign sign --keyless (Rekor upload OFF)
```

HarborMirror reconciler still ships **dormant** —
`gameWardenForwarding.enabled=false` at every layer.

## Prerequisites (one-time, laptop)

1. **kubectl context reaches pleme-dev.** Verify with:
   ```sh
   kubectl --context=pleme-dev -n zot-system get svc zot
   # expect: a ClusterIP Service on port 5000
   ```
   If your kubeconfig doesn't have a pleme-dev context, fetch
   `/etc/rancher/k3s/k3s.yaml` from the pleme-dev server node and
   rewrite the `server:` field from `127.0.0.1` to the node's
   internal IP / Tailscale name / wherever the apiserver listens.

2. **SOPS age key for pleme-dev.** Needed to decrypt the
   `akeyless-builder` push token + to encrypt the new
   `zot-pull-secret.sops.yaml`. Standard pleme-io developer setup
   (`~/.config/sops/age/keys.txt`).

3. **Dev shell with the private-publish toolchain:**
   ```sh
   cd ~/code/github/pleme-io/engenho-promessa-controllers
   nix develop   # brings skopeo + kubectl + cosign + sops onto PATH
   ```

## Step 1 — Encrypt `zot-pull-secret.sops.yaml` (one-time)

A placeholder Secret was committed at
`pleme-io/k8s/clusters/pleme-dev/apps/akeyless-validation/zot-pull-secret.sops.yaml`.
The file's header has the exact `sops --encrypt` recipe. Run it,
commit the resulting encrypted file, push to `pleme-io/k8s@main`.

Flux will pick up within the GitRepository's 5-minute interval.
Once the Secret materializes, the HelmRelease's Deployments stop
ImagePullBackOff on the next reconcile.

## Step 2 — Private push from laptop

Single command, fully automated (kubectl port-forward + skopeo copy +
cosign keyless signing, all under `--dest-tls-verify=false` because
the in-cluster Zot speaks plain HTTP on the Service IP):

```sh
cd ~/code/github/pleme-io/engenho-promessa-controllers
scripts/private-push.sh engenho-promessa validation-api
```

What it does:
1. `kubectl -n zot-system port-forward svc/zot 5000:5000` (background)
2. `sops -d zot-push-token.sops.yaml | yq -r '.data.token' | base64 -d` → `$TOKEN`
3. `skopeo login --tls-verify=false localhost:5000 --username akeyless-builder --password "$TOKEN"`
4. For each binary:
   - `nix build .#"image:<binary>"`
   - `skopeo copy --dest-tls-verify=false docker-archive:./result docker://localhost:5000/pleme-io/<binary>:0.2.0`
   - `cosign sign --yes --tlog-upload=false localhost:5000/pleme-io/<binary>@sha256:<digest>`
     (Rekor upload disabled — Rekor is public. D-OP-9 will deploy an
     internal Rekor or we explicitly opt into transparency later.)
5. Tears down port-forward

Override flags:
```sh
scripts/private-push.sh --kube-context pleme-dev --tag 0.2.1 engenho-promessa
PRIVATE_PUSH_SKIP_COSIGN=1 scripts/private-push.sh engenho-promessa  # iterate without re-signing
```

## Step 3 — Bump pleme-io/k8s helmrelease

The `clusters/pleme-dev/apps/akeyless-validation/helmrelease.yaml`
already references the cluster-internal Zot Service hostname + the
`zot-pull-secret` imagePullSecret. If the image tag in your push
matches the helmrelease tag, flux rolls automatically on the next
reconcile (10m). If you bumped (e.g., 0.2.0 → 0.2.1):

```sh
cd ~/code/github/pleme-io/k8s
yq -i '.spec.values.controller.image.tag = "0.2.1"' \
   clusters/pleme-dev/apps/akeyless-validation/helmrelease.yaml
yq -i '.spec.values.api.image.tag = "0.2.1"' \
   clusters/pleme-dev/apps/akeyless-validation/helmrelease.yaml
git commit -am "akeyless-validation: bump to 0.2.1"
git push
```

## Step 4 — Verify

```sh
# Image came from internal Zot, NOT a third-party registry
kubectl -n akeyless-validation describe pod \
    -l app.kubernetes.io/component=controller | grep Image:
# expect: Image: zot.zot-system.svc.cluster.local:5000/pleme-io/engenho-promessa:0.2.0

# Pull-secret is the new zot-pull-secret
kubectl -n akeyless-validation get pod \
    -l app.kubernetes.io/component=controller \
    -o jsonpath='{.items[0].spec.imagePullSecrets[*].name}'
# expect: zot-pull-secret

# Controller booted the validation-store
kubectl -n akeyless-validation logs deploy/akeyless-validation-controller \
    | grep -E "validation-store schema ensured|action_dispatcher starting"

# PVC bound
kubectl -n akeyless-validation get pvc akeyless-validation-store

# Cosign signature visible on the image (via kubectl exec into
# any pod that has cosign — or from your laptop via port-forward):
kubectl -n zot-system port-forward svc/zot 5000:5000 &
cosign verify --allow-insecure-registry --insecure-ignore-tlog \
    --certificate-identity=<your-oidc-email> \
    --certificate-oidc-issuer=https://accounts.google.com \
    localhost:5000/pleme-io/engenho-promessa:0.2.0
# (substitute your OIDC issuer + email used at signing time)
```

## Three rings of privacy, in order

| Ring | Status after this deploy |
|---|---|
| **R1** — Akeyless-source binaries off ghcr.io, on Zot only | ✅ Live |
| **R2** — Laptop push bypasses Cloudflare Edge (kubectl port-forward) | ✅ Live (via `scripts/private-push.sh`) |
| **R3** — `forge image-release` multi-arch + lacre admit gate in front of Zot | ❌ Deferred to D-OP-9 |

## Cloudflare Tunnel — still useful, scoped down

The CF Tunnel at `zot-dev.quero.cloud` is **not the operator's push
path anymore**. It's retained for:
- Read-side access from other clusters / future CI runners pulling
  approved digests (cartorio-Active only — lacre will enforce this in
  R3)
- Operator's ad-hoc image inspection from off-cluster

This change does NOT remove the CF Tunnel — it just stops using it
for the push path. If you want to eliminate CF entirely, remove the
zot-tunnel HelmRelease + the rio-side CloudflareTunnel CR; everything
in-cluster keeps working since pulls already use the Service IP.
