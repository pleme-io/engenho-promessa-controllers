//! `DbCli` — generic table-management helpers for any SeaORM entity.
//! Lifted verbatim from the kiroku pattern (idiom-first); the only
//! difference is the scoped naming.

use sea_orm::entity::prelude::*;
use sea_orm::{DatabaseConnection, Schema};

use crate::store::StoreError;

/// Database CLI operations for any entity. All methods are generic
/// over [`EntityTrait`] so they work for every entity in
/// [`crate::entities`].
pub struct DbCli;

impl DbCli {
    /// Create the entity's table if it doesn't exist. Idempotent.
    pub async fn create_table<E>(db: &DatabaseConnection) -> Result<(), StoreError>
    where
        E: EntityTrait,
    {
        let builder = db.get_database_backend();
        let schema = Schema::new(builder);
        let mut stmt = schema.create_table_from_entity(E::default());
        stmt.if_not_exists();
        db.execute(builder.build(&stmt)).await?;
        Ok(())
    }

    /// Drop and recreate the entity's table. Destructive — wipes
    /// all rows.
    pub async fn reset_table<E>(db: &DatabaseConnection) -> Result<(), StoreError>
    where
        E: EntityTrait,
    {
        let builder = db.get_database_backend();
        let drop_stmt = sea_orm::sea_query::Table::drop()
            .table(E::default())
            .if_exists()
            .to_owned();
        db.execute(builder.build(&drop_stmt)).await?;

        let schema = Schema::new(builder);
        let create_stmt = schema.create_table_from_entity(E::default());
        db.execute(builder.build(&create_stmt)).await?;
        Ok(())
    }

    /// Count rows in the entity's table.
    pub async fn count<E>(db: &DatabaseConnection) -> Result<u64, StoreError>
    where
        E: EntityTrait,
        E::Model: Sync,
    {
        let count = E::find().count(db).await?;
        Ok(count)
    }
}
