//! The transport under IMAP (M4 spec §6.1): implicit TLS through rustls
//! with the Mozilla roots, or plaintext to a loopback address only (tests
//! against GreenMail and the scripted server). Never plaintext elsewhere.

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::account::is_loopback_host;
use crate::error::MailError;

/// TLS or loopback plaintext.
pub enum MailStream {
    /// TLS.
    Tls(Box<TlsStream<TcpStream>>),
    /// Plaintext to loopback.
    Plain(TcpStream),
}

impl std::fmt::Debug for MailStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MailStream::Tls(_) => "MailStream::Tls",
            MailStream::Plain(_) => "MailStream::Plain",
        })
    }
}

impl AsyncRead for MailStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            MailStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MailStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
            MailStream::Plain(s) => Pin::new(s).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            MailStream::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            MailStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// The shared client configuration. The ring provider is named explicitly so
/// this crate works without any process-wide provider installed (the CLI
/// runner and `cargo test -p inumaki-mail` reach this code before the daemon
/// or the gateway installs one).
fn tls_config() -> Result<Arc<rustls::ClientConfig>, MailError> {
    static CONFIG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Some(Arc::new(config))
        })
        .clone()
        .ok_or(MailError::Tls("config"))
}

/// Connect within `timeout`. Plaintext is refused unless `host` is loopback.
pub async fn connect_stream(
    host: &str,
    port: u16,
    tls: bool,
    timeout: Duration,
) -> Result<MailStream, MailError> {
    if !tls && !is_loopback_host(host) {
        return Err(MailError::Tls("plaintext_not_loopback"));
    }
    let tcp = match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(MailError::Unreachable(e.kind())),
        Err(_) => return Err(MailError::Timeout),
    };
    let _ = tcp.set_nodelay(true);
    if !tls {
        return Ok(MailStream::Plain(tcp));
    }
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| MailError::Tls("server_name"))?;
    let connector = tokio_rustls::TlsConnector::from(tls_config()?);
    match tokio::time::timeout(timeout, connector.connect(name, tcp)).await {
        Ok(Ok(s)) => Ok(MailStream::Tls(Box::new(s))),
        Ok(Err(_)) => Err(MailError::Tls("handshake")),
        Err(_) => Err(MailError::Timeout),
    }
}
