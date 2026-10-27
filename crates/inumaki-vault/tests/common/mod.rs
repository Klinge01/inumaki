//! Shared helpers for the migration tests. A schema renumber touches
//! [`downgrade_to`] only (add one `if version < N` block per new version).

#![allow(dead_code)]

/// Turn a current-version vault file into one that looks like schema
/// `version`: drop everything later versions added and set
/// `meta.schema_version`, so the next open walks the migrations from there.
pub fn downgrade_to(conn: &rusqlite::Connection, version: u32) {
    let mut sql = String::new();
    if version < 7 {
        sql.push_str("DROP TABLE mirror_files; DROP TABLE folders;");
    }
    if version < 6 {
        sql.push_str("DROP INDEX entries_surface_of; ALTER TABLE entries DROP COLUMN surface_of;");
    }
    if version < 5 {
        sql.push_str("DROP TABLE mail_handles; DROP TABLE mailboxes;");
    }
    if version < 4 {
        sql.push_str(
            "DROP TABLE journal; ALTER TABLE entries DROP COLUMN created_at; \
             ALTER TABLE entries DROP COLUMN uses;",
        );
    }
    if version < 3 {
        sql.push_str("DROP TABLE activity;");
    }
    sql.push_str(&format!(
        "UPDATE meta SET value = '{version}' WHERE key = 'schema_version';"
    ));
    conn.execute_batch(&sql).unwrap();
}
