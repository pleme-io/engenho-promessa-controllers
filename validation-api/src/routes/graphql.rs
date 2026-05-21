//! GraphQL schema — typed projection over `ValidationProjection`.
//!
//! M1.5: read-only Query root over validations/tenants/scan-jobs.
//! M2 will add Subscription root for phase-transition streams.

use std::sync::Arc;

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use validation_crds::{AkeylessEphemeralTenant, AkeylessImageValidation, ScanJob};

use crate::projection::ValidationProjection;

pub type ValidationSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

pub fn build_schema(p: Arc<ValidationProjection>) -> ValidationSchema {
    Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
        .data(p)
        .finish()
}

pub fn sdl() -> String {
    let dummy = Arc::new(ValidationProjection::new());
    build_schema(dummy).sdl()
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Every AkeylessImageValidation observed by the API's informer.
    async fn validations(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<ValidationView>> {
        let p = ctx.data::<Arc<ValidationProjection>>()?;
        let snap = p.snapshot().await;
        Ok(snap.validations.into_iter().map(ValidationView::from).collect())
    }

    /// A single validation by namespace + name.
    async fn validation(
        &self,
        ctx: &Context<'_>,
        namespace: String,
        name: String,
    ) -> async_graphql::Result<Option<ValidationView>> {
        let p = ctx.data::<Arc<ValidationProjection>>()?;
        Ok(p.get_validation(&namespace, &name).await.map(ValidationView::from))
    }

    /// Every AkeylessEphemeralTenant currently observed.
    async fn ephemeral_tenants(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Vec<TenantView>> {
        let p = ctx.data::<Arc<ValidationProjection>>()?;
        let snap = p.snapshot().await;
        Ok(snap.tenants.into_iter().map(TenantView::from).collect())
    }

    /// Every ScanJob currently observed.
    async fn scan_jobs(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<ScanJobView>> {
        let p = ctx.data::<Arc<ValidationProjection>>()?;
        let snap = p.snapshot().await;
        Ok(snap.scan_jobs.into_iter().map(ScanJobView::from).collect())
    }

    /// Compliance health rollup.
    async fn compliance_state(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        let p = ctx.data::<Arc<ValidationProjection>>()?;
        let snap = p.snapshot().await;
        let mut state = "Cosmetic";
        for v in &snap.validations {
            if let Some(gd) = v.status.as_ref().and_then(|s| s.gate_decision.as_ref()) {
                match gd.severity.as_str() {
                    "Critical" => return Ok("Critical".into()),
                    "Functional" if state == "Cosmetic" => state = "Functional",
                    _ => {}
                }
            }
        }
        Ok(state.into())
    }
}

// ── GraphQL views — typed projections over the raw CR types ────────

#[derive(async_graphql::SimpleObject, Debug, Clone)]
pub struct ValidationView {
    pub name: String,
    pub namespace: String,
    pub service: String,
    pub image_digest: String,
    pub promessa_ref: String,
    pub phase: String,
    pub severity: Option<String>,
    pub verdict: Option<String>,
    pub findings_count: u64,
}

impl From<AkeylessImageValidation> for ValidationView {
    fn from(v: AkeylessImageValidation) -> Self {
        let status = v.status.as_ref();
        let phase = status
            .and_then(|s| s.phase)
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "Unknown".into());
        let (severity, verdict) = status
            .and_then(|s| s.gate_decision.as_ref())
            .map(|gd| (Some(gd.severity.clone()), Some(format!("{:?}", gd.verdict))))
            .unwrap_or((None, None));
        let findings_count = status
            .map(|s| s.scan_jobs.iter().map(|sj| sj.findings_count).sum())
            .unwrap_or(0);
        Self {
            name: v.metadata.name.clone().unwrap_or_default(),
            namespace: v.metadata.namespace.clone().unwrap_or_default(),
            service: v.spec.service,
            image_digest: v.spec.image_digest,
            promessa_ref: v.spec.promessa_ref,
            phase,
            severity,
            verdict,
            findings_count,
        }
    }
}

#[derive(async_graphql::SimpleObject, Debug, Clone)]
pub struct TenantView {
    pub name: String,
    pub namespace: String,
    pub phase: String,
    pub ingress_url: Option<String>,
    pub pods_ready: u32,
    pub pods_total: u32,
}

impl From<AkeylessEphemeralTenant> for TenantView {
    fn from(t: AkeylessEphemeralTenant) -> Self {
        let status = t.status.as_ref();
        let phase = status
            .and_then(|s| s.phase)
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "Unknown".into());
        Self {
            name: t.metadata.name.clone().unwrap_or_default(),
            namespace: t.metadata.namespace.clone().unwrap_or_default(),
            phase,
            ingress_url: status.and_then(|s| s.ingress_url.clone()),
            pods_ready: status.map(|s| s.pods_ready).unwrap_or(0),
            pods_total: status.map(|s| s.pods_total).unwrap_or(0),
        }
    }
}

#[derive(async_graphql::SimpleObject, Debug, Clone)]
pub struct ScanJobView {
    pub name: String,
    pub namespace: String,
    pub scanner: String,
    pub scanner_class: String,
    pub parent: String,
    pub phase: String,
    pub findings_count: u64,
}

impl From<ScanJob> for ScanJobView {
    fn from(j: ScanJob) -> Self {
        let status = j.status.as_ref();
        let phase = status
            .and_then(|s| s.phase)
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "Unknown".into());
        Self {
            name: j.metadata.name.clone().unwrap_or_default(),
            namespace: j.metadata.namespace.clone().unwrap_or_default(),
            scanner: format!("{:?}", j.spec.scanner),
            scanner_class: format!("{:?}", j.spec.scanner_class),
            parent: j.spec.parent_validation,
            phase,
            findings_count: status.map(|s| s.findings_count).unwrap_or(0),
        }
    }
}
