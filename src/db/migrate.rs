use rusqlite::Connection;

use crate::error::Result;

/// Run schema creation/migrations for baseline and audit databases.
///
/// With JSON blob columns, most type evolution does not require SQL migrations.
pub fn migrate_all(baseline_conn: &Connection, audit_conn: &Connection) -> Result<()> {
    crate::db::schema::create_baseline_tables(baseline_conn)?;
    crate::db::schema::create_audit_tables(audit_conn)?;
    Ok(())
}
