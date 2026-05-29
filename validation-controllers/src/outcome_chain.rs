//! `OutcomeChainAppender` — background fiber that subscribes to
//! AkeylessImageValidation phase transitions reaching terminal
//! states and appends a typed `OutcomeReceipt` (BLAKE3 digest + real
//! Ed25519 signature) to the validation's status.
//!
//! The signature is produced with the publisher's Ed25519 key (same
//! algorithm + identity model as cartorio/tabeliao) and is verifiable
//! by an auditor (kensa) holding only the public key — see
//! [`verifying_key_hex`] which the appender logs at startup for
//! deployment into the verifier policy.

use std::sync::Arc;

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
use kube::api::{Patch, PatchParams};
use kube::runtime::watcher::{watcher, Config, Event};
use kube::{Api, ResourceExt};
use serde_json::json;
use tracing::{info, warn};
use validation_crds::{
    AkeylessImageValidation, AkeylessImageValidationPhase, OutcomeReceiptRef,
};

use crate::context::ReconcileCtx;

#[derive(Debug, Clone, Default)]
pub struct OutcomeChainAppender;

/// Load the OutcomeChain Ed25519 signing key.
///
/// Reads a 32-byte seed from `OUTCOME_CHAIN_SIGNING_SEED` (64 hex
/// chars). Falls back to a deterministic dev seed with a loud warning
/// when unset/invalid — receipts then verify structurally but are NOT
/// production-trustworthy until a real publisher key is wired (via a
/// mounted secret / cofre).
fn load_signing_key() -> SigningKey {
    match std::env::var("OUTCOME_CHAIN_SIGNING_SEED")
        .ok()
        .and_then(|h| const_hex::decode(h.trim()).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    {
        Some(seed) => SigningKey::from_bytes(&seed),
        None => {
            warn!(
                "OUTCOME_CHAIN_SIGNING_SEED unset/invalid — using a deterministic \
                 dev seed; OutcomeChain receipts are NOT production-trustworthy \
                 until a real publisher key is provided"
            );
            SigningKey::from_bytes(&[0x5au8; 32])
        }
    }
}

/// The publisher's Ed25519 public key, hex-encoded — deploy this into
/// the kensa/verifier policy so receipts can be verified offline.
fn verifying_key_hex(signing_key: &SigningKey) -> String {
    const_hex::encode(signing_key.verifying_key().to_bytes())
}

pub async fn run(ctx: Arc<ReconcileCtx>) -> anyhow::Result<()> {
    let api: Api<AkeylessImageValidation> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    let signing_key = load_signing_key();
    info!(
        public_key_hex = %verifying_key_hex(&signing_key),
        "OutcomeChainAppender starting (Ed25519 publisher key — deploy to verifier policy)"
    );
    let mut stream = std::pin::pin!(watcher(api.clone(), Config::default()));
    while let Some(ev) = stream.next().await {
        match ev {
            Ok(Event::Apply(obj)) | Ok(Event::InitApply(obj)) => {
                handle(api.clone(), obj, &signing_key).await;
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "outcome-chain watcher error"),
        }
    }
    Ok(())
}

async fn handle(
    api: Api<AkeylessImageValidation>,
    obj: AkeylessImageValidation,
    signing_key: &SigningKey,
) {
    let Some(phase) = obj.status.as_ref().and_then(|s| s.phase) else {
        return;
    };
    let terminal = matches!(
        phase,
        AkeylessImageValidationPhase::Passed
            | AkeylessImageValidationPhase::Failed
            | AkeylessImageValidationPhase::Quarantined
    );
    if !terminal {
        return;
    }
    let already_signed = obj
        .status
        .as_ref()
        .and_then(|s| s.outcome_receipt_ref.as_ref())
        .is_some();
    if already_signed {
        return;
    }
    let receipt = build_receipt(&obj, signing_key);
    let name = obj.name_any();
    let patch = json!({ "status": { "outcomeReceiptRef": receipt } });
    let pp = PatchParams::apply("validation-controllers");
    if let Err(e) = api.patch_status(&name, &pp, &Patch::Merge(&patch)).await {
        warn!(error = %e, "failed to append outcome receipt");
    } else {
        info!(name = %name, hash = %receipt.blake3_hash, "outcome receipt appended");
    }
}

/// The canonical signable content for a validation's outcome receipt.
fn canonical_content(obj: &AkeylessImageValidation) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        obj.spec.service,
        obj.spec.image_digest,
        obj.status
            .as_ref()
            .and_then(|s| s.gate_decision.as_ref())
            .map(|gd| format!("{:?}", gd.verdict))
            .unwrap_or_default(),
        obj.status
            .as_ref()
            .and_then(|s| s.gate_decision.as_ref())
            .map(|gd| gd.severity.clone())
            .unwrap_or_default(),
        obj.status
            .as_ref()
            .and_then(|s| s.evidence_bundle_hash.clone())
            .unwrap_or_default(),
    )
}

/// Compute the BLAKE3 digest of the canonical content and a real
/// Ed25519 signature over that digest. Returns `(blake3_hex, sig_hex)`.
///
/// Pure + deterministic: the same content + key always yields the same
/// pair, and the signature verifies against the signer's public key
/// alone (the property the empty `ed25519_sig` placeholder lacked).
fn sign_canonical(signing_key: &SigningKey, canonical: &str) -> (String, String) {
    let digest = blake3::hash(canonical.as_bytes());
    let sig = signing_key.sign(digest.as_bytes());
    (
        digest.to_hex().to_string(),
        const_hex::encode(sig.to_bytes()),
    )
}

fn build_receipt(obj: &AkeylessImageValidation, signing_key: &SigningKey) -> OutcomeReceiptRef {
    let canonical = canonical_content(obj);
    let (hash, sig) = sign_canonical(signing_key, &canonical);
    OutcomeReceiptRef {
        minio_path: format!(
            "s3://outcome-chains-pleme-dev/akeyless-nix-images-fedramp-scr/{hash}.json"
        ),
        blake3_hash: hash,
        ed25519_sig: sig,
        signed_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn sign_canonical_produces_verifiable_ed25519() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let (hash_hex, sig_hex) = sign_canonical(&key, "auth|sha256:abc|Passed|none|bundle");

        // The signature is a real 64-byte Ed25519 sig (not empty).
        let sig_bytes = const_hex::decode(&sig_hex).unwrap();
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature is 64 bytes");
        assert!(!sig_hex.is_empty(), "ed25519_sig must not be the empty placeholder");

        // An auditor with ONLY the public key verifies it over the digest.
        let digest = const_hex::decode(&hash_hex).unwrap();
        let sig = Signature::from_bytes(&<[u8; 64]>::try_from(sig_bytes.as_slice()).unwrap());
        assert!(
            key.verifying_key().verify(&digest, &sig).is_ok(),
            "signature must verify against the publisher public key"
        );
    }

    #[test]
    fn sign_canonical_deterministic_and_content_bound() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let a1 = sign_canonical(&key, "svc|d1|Passed|none|b1");
        let a2 = sign_canonical(&key, "svc|d1|Passed|none|b1");
        assert_eq!(a1, a2, "same content + key is deterministic");

        let b = sign_canonical(&key, "svc|d2|Failed|critical|b2");
        assert_ne!(a1.0, b.0, "different content → different digest");
        assert_ne!(a1.1, b.1, "different content → different signature");
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let signer = SigningKey::from_bytes(&[5u8; 32]);
        let impostor = SigningKey::from_bytes(&[6u8; 32]);
        let (hash_hex, sig_hex) = sign_canonical(&signer, "svc|d|Passed|none|b");

        let digest = const_hex::decode(&hash_hex).unwrap();
        let sig_bytes = const_hex::decode(&sig_hex).unwrap();
        let sig = Signature::from_bytes(&<[u8; 64]>::try_from(sig_bytes.as_slice()).unwrap());
        assert!(
            impostor.verifying_key().verify(&digest, &sig).is_err(),
            "a different publisher key must not verify the signature"
        );
    }
}
