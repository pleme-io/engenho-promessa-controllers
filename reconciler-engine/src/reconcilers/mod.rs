//! Concrete [`promessa_types::Reconciler`] implementations. Each
//! wraps exactly one substrate primitive per the wrap-not-compete
//! invariant (VIGGY-AUTHORING §3.3) — typed inputs in, typed receipt
//! out, no re-implementation of the underlying ledger/registry/git
//! logic.

pub mod cartorio_admit;
pub mod flux_commit;
pub mod ghcr_tag_revoke;
pub mod harbor_mirror;
