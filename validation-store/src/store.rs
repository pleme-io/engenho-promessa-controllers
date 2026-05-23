//! `ValidationStore` — dual-runtime SeaORM wrapper for the
//! AKEYLESS-VALIDATION-PLATFORM persistence layer. Copy of the
//! `kiroku::MetadataStore` shape (idiom-first per VIGGY-AUTHORING
//! §3.1 — re-use the proven dual sync/async wrapper instead of
//! inventing a new one).
//!
//! ## Two modes
//!
//! - **Sync** ([`ValidationStore::open_sqlite`] /
//!   [`ValidationStore::connect`]): owns a tokio runtime and blocks
//!   on async ops. Used by CLI tools + REST handlers running on
//!   axum's worker pool when the handler itself isn't async.
//! - **Async** ([`ValidationStore::connect_async`]): uses the
//!   caller's existing runtime. Used by the validation-api binary,
//!   the action_dispatcher, and any kube-rs reconciler that wants
//!   to read/write store rows.
//!
//! Both modes expose [`ValidationStore::db`] for direct SeaORM ops
//! and [`ValidationStore::block_on`] for the sync/async bridge.

use std::future::Future;
use std::path::Path;

use sea_orm::{Database, DatabaseConnection};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("connect: {0}")]
    Connect(#[from] sea_orm::DbErr),

    #[error("runtime: {0}")]
    Runtime(#[from] std::io::Error),
}

enum Runtime {
    Owned(tokio::runtime::Runtime),
    External,
}

/// A SeaORM connection to the validation-store database with dual
/// sync/async runtime support.
pub struct ValidationStore {
    db: DatabaseConnection,
    rt: Runtime,
}

impl ValidationStore {
    /// Open a SQLite database at the given path (sync, owns runtime).
    /// Creates the file with `?mode=rwc` if absent.
    pub fn open_sqlite(db_path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let url = format!("sqlite://{}?mode=rwc", db_path.as_ref().display());
        Self::connect(&url)
    }

    /// Connect to any SeaORM-supported database (sync, owns runtime).
    /// Use this for CLIs (`validation-store migrate`, etc.) where
    /// there's no enclosing tokio runtime.
    pub fn connect(database_url: &str) -> Result<Self, StoreError> {
        let rt = tokio::runtime::Runtime::new()?;
        let db = rt.block_on(Database::connect(database_url))?;
        Ok(Self { db, rt: Runtime::Owned(rt) })
    }

    /// Connect (async, uses the caller's runtime). Use this from
    /// inside `#[tokio::main]` binaries.
    pub async fn connect_async(database_url: &str) -> Result<Self, StoreError> {
        let db = Database::connect(database_url).await?;
        Ok(Self { db, rt: Runtime::External })
    }

    /// Convenience: open an in-memory SQLite database. Tests only —
    /// each call returns a fresh isolated DB.
    pub async fn in_memory() -> Result<Self, StoreError> {
        Self::connect_async("sqlite::memory:").await
    }

    /// Direct access to the SeaORM connection.
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Run a future, blocking if sync mode or using `block_in_place`
    /// if async. Lets sync handlers call async SeaORM ops without
    /// spawning new tasks.
    pub fn block_on<F: Future>(&self, f: F) -> F::Output {
        match &self.rt {
            Runtime::Owned(rt) => rt.block_on(f),
            Runtime::External => {
                tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn in_memory_opens() {
        let store = ValidationStore::in_memory().await.unwrap();
        let _db = store.db();
    }

    #[tokio::test]
    async fn connect_async_sqlite() {
        let dir = TempDir::new().unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.path().join("test.db").display());
        let store = ValidationStore::connect_async(&url).await.unwrap();
        let _db = store.db();
    }

    #[test]
    fn open_sqlite_sync() {
        let dir = TempDir::new().unwrap();
        let store = ValidationStore::open_sqlite(dir.path().join("test.db")).unwrap();
        let _db = store.db();
    }

    #[test]
    fn block_on_owned_runtime_executes_future() {
        let dir = TempDir::new().unwrap();
        let store = ValidationStore::open_sqlite(dir.path().join("test.db")).unwrap();
        let answer = store.block_on(async { 42_u32 });
        assert_eq!(answer, 42);
    }
}
