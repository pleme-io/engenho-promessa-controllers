//! Typed projection of the three CRDs — the single source of truth
//! every transport reads. Updated only by kube-rs informers; read-only
//! to consumers.

use std::collections::BTreeMap;
use std::sync::Arc;

use kube::runtime::watcher::{watcher, Config, Event};
use kube::{Api, Client};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
#[allow(unused_imports)]
use validation_crds::{AkeylessEphemeralTenant, AkeylessImageValidation, ScanJob};

/// Read-only typed snapshot exposed to all transports.
#[derive(Debug, Default)]
pub struct ValidationProjection {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
pub(crate) struct Inner {
    /// Keyed by `<namespace>/<name>`.
    pub validations: BTreeMap<String, AkeylessImageValidation>,
    pub tenants: BTreeMap<String, AkeylessEphemeralTenant>,
    pub scan_jobs: BTreeMap<String, ScanJob>,
}

impl ValidationProjection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self) -> Snapshot {
        let g = self.inner.read().await;
        Snapshot {
            validations: g.validations.values().cloned().collect(),
            tenants: g.tenants.values().cloned().collect(),
            scan_jobs: g.scan_jobs.values().cloned().collect(),
        }
    }

    pub async fn get_validation(&self, ns: &str, name: &str) -> Option<AkeylessImageValidation> {
        let g = self.inner.read().await;
        g.validations.get(&key(ns, name)).cloned()
    }
    pub async fn get_tenant(&self, ns: &str, name: &str) -> Option<AkeylessEphemeralTenant> {
        let g = self.inner.read().await;
        g.tenants.get(&key(ns, name)).cloned()
    }
    pub async fn get_scan_job(&self, ns: &str, name: &str) -> Option<ScanJob> {
        let g = self.inner.read().await;
        g.scan_jobs.get(&key(ns, name)).cloned()
    }

    /// Spawn three kube-rs informers — one per CRD. Each runs as a
    /// detached tokio task; the projection updates on every Applied /
    /// Deleted event. Restarts on watcher error with exponential backoff.
    pub async fn spawn_informers(self: Arc<Self>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let cfg = Config::default();

        // AkeylessImageValidation
        let cfg_iv = cfg.clone();
        let cfg_eph = cfg.clone();
        let cfg_sj = cfg;
        {
            let p = self.clone();
            let api: Api<AkeylessImageValidation> = Api::all(client.clone());
            tokio::spawn(async move {
                run_watcher(p, api, cfg_iv, |inner, ev| match ev {
                    Event::Apply(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.validations.insert(k, o);
                        }
                    }
                    Event::Delete(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.validations.remove(&k);
                        }
                    }
                    Event::Init => {
                        inner.validations.clear();
                    }
                    Event::InitApply(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.validations.insert(k, o);
                        }
                    }
                    Event::InitDone => {}
                })
                .await;
            });
        }

        // AkeylessEphemeralTenant
        {
            let p = self.clone();
            let api: Api<AkeylessEphemeralTenant> = Api::all(client.clone());
            tokio::spawn(async move {
                run_watcher(p, api, cfg_eph, |inner, ev| match ev {
                    Event::Apply(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.tenants.insert(k, o);
                        }
                    }
                    Event::Delete(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.tenants.remove(&k);
                        }
                    }
                    Event::Init => {
                        inner.tenants.clear();
                    }
                    Event::InitApply(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.tenants.insert(k, o);
                        }
                    }
                    Event::InitDone => {}
                })
                .await;
            });
        }

        // ScanJob
        {
            let p = self.clone();
            let api: Api<ScanJob> = Api::all(client.clone());
            tokio::spawn(async move {
                run_watcher(p, api, cfg_sj, |inner, ev| match ev {
                    Event::Apply(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.scan_jobs.insert(k, o);
                        }
                    }
                    Event::Delete(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.scan_jobs.remove(&k);
                        }
                    }
                    Event::Init => {
                        inner.scan_jobs.clear();
                    }
                    Event::InitApply(o) => {
                        if let Some(k) = key_of(&o) {
                            inner.scan_jobs.insert(k, o);
                        }
                    }
                    Event::InitDone => {}
                })
                .await;
            });
        }

        info!("informers spawned for all 3 CRDs");
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub validations: Vec<AkeylessImageValidation>,
    pub tenants: Vec<AkeylessEphemeralTenant>,
    pub scan_jobs: Vec<ScanJob>,
}

fn key(ns: &str, name: &str) -> String {
    format!("{ns}/{name}")
}

fn key_of<R: kube::ResourceExt>(o: &R) -> Option<String> {
    let name = o.name_any();
    let ns = o.namespace().unwrap_or_default();
    if name.is_empty() {
        None
    } else {
        Some(key(&ns, &name))
    }
}

async fn run_watcher<R, F>(p: Arc<ValidationProjection>, api: Api<R>, cfg: Config, mut apply: F)
where
    R: kube::Resource + Clone + std::fmt::Debug + Send + Sync + 'static,
    R::DynamicType: Default + std::hash::Hash + Eq + Clone + std::fmt::Debug,
    R: for<'de> serde::Deserialize<'de>,
    F: FnMut(&mut Inner, Event<R>),
{
    use futures::StreamExt;
    let mut stream = std::pin::pin!(watcher(api, cfg));
    while let Some(ev) = stream.next().await {
        match ev {
            Ok(e) => {
                let mut g = p.inner.write().await;
                apply(&mut g, e);
            }
            Err(err) => {
                error!(?err, "watcher error; will restart");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
    warn!("watcher stream ended unexpectedly");
}
