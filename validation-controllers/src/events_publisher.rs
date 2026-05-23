//! NATS publisher for the security-posture stream.
//!
//! Every meaningful change in the validation pipeline emits one
//! typed [`validation_events::ValidationEvent`] on a canonical NATS
//! subject (`validation.posture.<service>.<event-kind>`). Downstream
//! consumers — alerters, dashboards, future kenshi cross-cluster
//! rebroadcast, audit-relay — subscribe by service or by event-kind
//! wildcard.
//!
//! ## Connection lifecycle
//!
//! - `NATS_URL` env set → connect at construction; publishes go to
//!   the broker; failures log + drop (validation pipeline keeps
//!   running). Eventually-consistent — durability is in the
//!   validation-store rows; NATS is the realtime fan-out.
//! - `NATS_URL` unset → constructor returns a `Disconnected` variant;
//!   every `publish` is a typed no-op. Lets dev/test runs proceed
//!   without a NATS broker in the loop.
//!
//! ## Why no `async-nats::jetstream`
//!
//! Core NATS is fire-and-forget pub/sub — exactly what we want. The
//! durable side of the stream IS the validation-store: a consumer
//! that misses an event can replay it via the REST/gRPC face on the
//! validation_run uid. JetStream would duplicate that durability
//! for no extra typed-substrate value.

use std::sync::Arc;

use thiserror::Error;
use validation_events::ValidationEvent;

#[derive(Clone)]
pub struct EventsPublisher {
    inner: Arc<Inner>,
}

enum Inner {
    /// Live connection. `client` is cheap to clone via Arc — the
    /// async-nats client is internally Arc'd.
    Connected { client: async_nats::Client },
    /// No NATS URL configured — every publish is a no-op.
    Disconnected,
}

#[derive(Error, Debug)]
pub enum PublishError {
    /// async-nats's publish error has a nested generic shape
    /// (`Error<PublishErrorKind>`); we capture it as a string so
    /// callers don't need to depend on the async-nats type stack.
    #[error("nats client: {0}")]
    Client(String),
    #[error("serialize event: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl EventsPublisher {
    /// Construct from env. Reads `NATS_URL` (and optionally
    /// `NATS_AUTH_TOKEN` for bearer auth). Returns a Disconnected
    /// publisher if `NATS_URL` is unset — every subsequent publish
    /// is a typed no-op.
    pub async fn from_env() -> Self {
        let Ok(url) = std::env::var("NATS_URL") else {
            tracing::info!(
                "events_publisher: NATS_URL unset — running in Disconnected mode; \
                 every publish is a no-op"
            );
            return Self { inner: Arc::new(Inner::Disconnected) };
        };
        Self::connect(&url).await
    }

    /// Construct with an explicit URL. Used by tests + by callers
    /// that want non-env config. No `retry_on_initial_connect()` —
    /// we want to know IMMEDIATELY if the broker is unreachable so
    /// the controller falls back to Disconnected mode rather than
    /// hanging on a retry loop. Once connected, async-nats handles
    /// reconnect/backoff internally.
    pub async fn connect(url: &str) -> Self {
        let mut opts = async_nats::ConnectOptions::new().name("validation-controllers");
        if let Ok(token) = std::env::var("NATS_AUTH_TOKEN") {
            opts = opts.token(token);
        }
        // Bound the connect to 5s — beyond that we treat the broker
        // as unreachable and fall back. async-nats has no built-in
        // connect timeout; wrap with tokio::time::timeout.
        let connect_fut = opts.connect(url);
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), connect_fut).await;
        match result {
            Ok(Ok(client)) => {
                tracing::info!(url = %url, "events_publisher: connected to NATS");
                Self { inner: Arc::new(Inner::Connected { client }) }
            }
            Ok(Err(err)) => {
                tracing::warn!(
                    url = %url, error = %err,
                    "events_publisher: NATS connect failed — falling back to Disconnected"
                );
                Self { inner: Arc::new(Inner::Disconnected) }
            }
            Err(_) => {
                tracing::warn!(
                    url = %url,
                    "events_publisher: NATS connect timed out after 5s — Disconnected"
                );
                Self { inner: Arc::new(Inner::Disconnected) }
            }
        }
    }

    /// Disconnected — for tests and offline/dev runs.
    #[must_use]
    pub fn disconnected() -> Self {
        Self { inner: Arc::new(Inner::Disconnected) }
    }

    /// Publish one typed event. The NATS subject is derived from
    /// the event variant via `ValidationEvent::subject()`. Failures
    /// log + drop; the caller's reconciler continues regardless.
    pub async fn publish(&self, event: &ValidationEvent) {
        match self.try_publish(event).await {
            Ok(()) => {
                tracing::trace!(subject = %event.subject(), "events_publisher: published");
            }
            Err(err) => {
                tracing::warn!(
                    subject = %event.subject(),
                    error = %err,
                    "events_publisher: publish failed; event dropped (durable copy is in validation-store)"
                );
            }
        }
    }

    /// Typed publish — exposed for tests + for callers that want
    /// to surface the error rather than log+drop.
    pub async fn try_publish(&self, event: &ValidationEvent) -> Result<(), PublishError> {
        let Inner::Connected { client } = self.inner.as_ref() else {
            return Ok(()); // Disconnected — typed no-op
        };
        let subject = event.subject();
        let body = serde_json::to_vec(event)?;
        client
            .publish(subject, body.into())
            .await
            .map_err(|e| PublishError::Client(e.to_string()))?;
        Ok(())
    }

    /// `true` if a real NATS connection is active. Useful for
    /// boot-time logging + the readyz probe.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self.inner.as_ref(), Inner::Connected { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use validation_events::{PhaseChanged, ValidationEvent};

    fn sample_event() -> ValidationEvent {
        use chrono::Utc;
        use validation_crds::AkeylessImageValidationPhase;
        ValidationEvent::PhaseChanged(PhaseChanged {
            event_id: validation_events::new_event_id(),
            validation_run_uid: "uid-test".into(),
            service: "auth".into(),
            image_digest: "sha256:abc".into(),
            image_repo: "akeyless-auth".into(),
            observed_at: Utc::now(),
            from: Some(AkeylessImageValidationPhase::Scanning),
            to: AkeylessImageValidationPhase::Passed,
        })
    }

    #[tokio::test]
    async fn disconnected_publishes_silently() {
        let pub_ = EventsPublisher::disconnected();
        assert!(!pub_.is_connected());
        // try_publish returns Ok(()) even though nothing was sent
        let r = pub_.try_publish(&sample_event()).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn disconnected_publish_is_idempotent() {
        let pub_ = EventsPublisher::disconnected();
        for _ in 0..5 {
            pub_.publish(&sample_event()).await; // doesn't panic
        }
    }

    #[tokio::test]
    async fn connect_to_bogus_url_falls_back_to_disconnected() {
        // 127.0.0.1:1 is the IANA "TCP port service multiplexer";
        // typically nothing's listening — connect should fail and
        // the publisher should fall back to Disconnected, not panic.
        let pub_ = EventsPublisher::connect("nats://127.0.0.1:1").await;
        assert!(!pub_.is_connected());
        // Still publishes silently
        pub_.publish(&sample_event()).await;
    }

    #[test]
    fn cloning_publisher_shares_inner() {
        // The Arc<Inner> means clones share the same connection;
        // multiple reconcilers can hold their own clone.
        let p1 = EventsPublisher::disconnected();
        let p2 = p1.clone();
        assert_eq!(p1.is_connected(), p2.is_connected());
    }
}
