//! Activity view (spec §6.4): records, verify, journal, entities, forget.
//! Originals come back only for an explicit reveal (`show_values = true`)
//! and go straight to the UI; nothing here stores or logs them. The
//! journal and entity routes arrive with plan 2b: before that they answer
//! `not_available` (a 404 `no such route`), while a 404 `not_found` of an
//! existing route stays an ordinary error.

use inumaki_client::{
    ActivityList, ActivityQuery, ActivityVerify, ClientError, EntityList, ForgetBody, JournalList,
    JournalRecord, Secret,
};
use serde::Serialize;

use crate::ctx::Ctx;
use crate::error::{CmdError, kind_ok};

/// Records newest first, without check datasets. Kind labels that fail
/// [`kind_ok`] are dropped, as in notifications and errors.
pub async fn activity(
    ctx: &Ctx,
    dataset: Option<String>,
    limit: Option<u64>,
) -> Result<ActivityList, CmdError> {
    let mut l = ctx
        .client
        .activity(&ActivityQuery {
            dataset,
            since: None,
            limit,
        })
        .await?;
    l.records.retain(|r| !r.dataset.starts_with("check-"));
    for r in &mut l.records {
        r.kinds.retain(|k| kind_ok(&k.kind));
    }
    Ok(l)
}

/// Verify the record chain.
pub async fn verify(ctx: &Ctx) -> Result<ActivityVerify, CmdError> {
    Ok(ctx.client.verify_activity().await?)
}

/// Journal of a dataset.
pub async fn journal(ctx: &Ctx, id: &str, since: Option<i64>) -> Result<JournalList, CmdError> {
    Ok(ctx.client.journal(id, since, Some(200)).await?)
}

/// One journal record; `reveal` asks for the originals (one item, one click).
pub async fn journal_record(
    ctx: &Ctx,
    id: &str,
    record: &str,
    reveal: bool,
) -> Result<JournalRecord, CmdError> {
    Ok(ctx.client.journal_record(id, record, reveal).await?)
}

/// Entity list; `reveal` asks for the originals.
pub async fn entities(ctx: &Ctx, id: &str, reveal: bool) -> Result<EntityList, CmdError> {
    Ok(ctx.client.entities(id, reveal, Some(500)).await?)
}

/// What a forget did. `purge_pending` is set when the mapping is gone but the
/// daemon's write-ahead-log purge is still running (`503 vault_busy`, spec §9.3
/// amendment): a success with a note, not an error.
#[derive(Debug, Serialize)]
pub struct ForgetOutcome {
    /// Kinds forgotten.
    pub kinds: Vec<String>,
    /// Tokens forgotten.
    pub tokens: u64,
    /// Rows deleted.
    pub rows: u64,
    /// The purge of the write-ahead log is still pending.
    pub purge_pending: bool,
}

fn forgotten(r: Result<ForgetBody, ClientError>) -> Result<ForgetOutcome, CmdError> {
    match r {
        Ok(b) => Ok(ForgetOutcome {
            kinds: b.kinds,
            tokens: b.tokens,
            rows: b.rows,
            purge_pending: false,
        }),
        Err(ClientError::Status {
            status: 503,
            error: Some(d),
        }) if d.kind == "vault_busy" => Ok(ForgetOutcome {
            kinds: Vec::new(),
            tokens: 0,
            rows: 0,
            purge_pending: true,
        }),
        Err(e) => Err(e.into()),
    }
}

/// Forget an entity by token.
pub async fn forget_token(ctx: &Ctx, id: &str, token: &str) -> Result<ForgetOutcome, CmdError> {
    forgotten(ctx.client.forget_token(id, token).await)
}

/// Forget an entity by typed value (password-style input, spec §6.5).
pub async fn forget_value(ctx: &Ctx, id: &str, value: String) -> Result<ForgetOutcome, CmdError> {
    let v = Secret::new(value);
    forgotten(ctx.client.forget_value(id, &v).await)
}
