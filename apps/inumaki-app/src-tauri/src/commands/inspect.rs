//! Inspect & recover (spec §6.4, M4 spec §9.1): nothing is fetched from an
//! upstream and nothing is retained. Offsets refer to the NFC-normalized
//! input's UTF-8 bytes; the UI converts them, and this module sends the
//! NFC text with the SHA-256 the daemon checks the redactions against.

use std::io::Read;
use std::path::Path;

use inumaki_client::{
    InspectBody, InspectRequest, Redaction, RedactionFile, SanitizeRequest, SanitizeResponse,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::ctx::Ctx;
use crate::error::CmdError;

/// Largest file the view opens.
const MAX_FILE: u64 = 1 << 20;

/// The NFC form the daemon's offsets refer to.
fn nfc(text: &str) -> String {
    text.nfc().collect()
}

/// An inspection with the exact text its span offsets index into: the UI
/// shows and slices `text`, never its own copy of the input.
#[derive(Serialize)]
pub struct InspectView {
    /// The NFC-normalized input; span offsets are UTF-8 bytes into it.
    pub text: String,
    /// The daemon's answer.
    pub body: InspectBody,
}

impl std::fmt::Debug for InspectView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectView")
            .field("text_len", &self.text.len())
            .field("body", &self.body)
            .finish()
    }
}

/// Inspect `text` with `dataset`; `show_values` reveals the span originals.
/// The text is NFC-normalized first, as for [`sanitize_with`], and the
/// normalized text comes back with the answer.
pub async fn inspect(
    ctx: &Ctx,
    dataset: &str,
    text: String,
    show_values: bool,
) -> Result<InspectView, CmdError> {
    let text = nfc(&text);
    let mut req = InspectRequest::new(dataset, text.clone());
    req.show_values = show_values;
    let body = ctx.client.inspect(&req).await?;
    Ok(InspectView { text, body })
}

/// Sanitize `text` with the user's redactions.
pub async fn sanitize_with(
    ctx: &Ctx,
    dataset: &str,
    text: String,
    spans: Vec<Redaction>,
) -> Result<SanitizeResponse, CmdError> {
    let nfc = nfc(&text);
    let sha: String = Sha256::digest(nfc.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut req = SanitizeRequest::dataset(dataset, nfc);
    req.redactions = Some(RedactionFile {
        input_sha256: sha,
        spans,
    });
    Ok(ctx.client.sanitize(&req).await?)
}

/// A local UTF-8 text file of at most 1 MiB, for the view to show. The
/// path comes from the Rust-side file picker, never from the UI; a
/// directory, a pipe, or a device is refused before it is opened for
/// reading (a pipe would block).
pub fn read_text_file(p: &Path) -> Result<String, CmdError> {
    let meta = std::fs::metadata(p).map_err(|_| CmdError::new("file_unreadable"))?;
    if !meta.is_file() {
        return Err(CmdError::new("file_not_text"));
    }
    if meta.len() > MAX_FILE {
        return Err(CmdError::new("file_too_large"));
    }
    let f = std::fs::File::open(p).map_err(|_| CmdError::new("file_unreadable"))?;
    // One byte more than the limit tells a file that grew since the check.
    let mut bytes = Vec::new();
    f.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CmdError::new("file_unreadable"))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(CmdError::new("file_too_large"));
    }
    String::from_utf8(bytes).map_err(|_| CmdError::new("file_not_text"))
}
