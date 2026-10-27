//! The route table (M8 spec §4): prefixes, upstream ids, served paths, and
//! the query strings harnesses are recorded to send.

use http::Method;

/// An upstream (integration spec §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamId {
    /// Anthropic API.
    Anthropic,
    /// OpenAI API.
    Openai,
    /// Codex ChatGPT backend.
    OpenaiCodex,
}

impl UpstreamId {
    /// In status order.
    pub const ALL: [UpstreamId; 3] = [
        UpstreamId::Anthropic,
        UpstreamId::Openai,
        UpstreamId::OpenaiCodex,
    ];

    /// `anthropic`, `openai`, `openai-codex`.
    pub fn id(self) -> &'static str {
        match self {
            UpstreamId::Anthropic => "anthropic",
            UpstreamId::Openai => "openai",
            UpstreamId::OpenaiCodex => "openai-codex",
        }
    }

    /// `/anthropic`, `/openai`, `/codex`.
    pub fn prefix(self) -> &'static str {
        match self {
            UpstreamId::Anthropic => "/anthropic",
            UpstreamId::Openai => "/openai",
            UpstreamId::OpenaiCodex => "/codex",
        }
    }

    /// From an upstream id.
    pub fn from_id(s: &str) -> Option<Self> {
        UpstreamId::ALL.into_iter().find(|u| u.id() == s)
    }

    /// Served paths relative to the prefix, as `GET /v1/proxy` lists them.
    pub fn served_paths(self) -> &'static [&'static str] {
        match self {
            UpstreamId::Anthropic => &[
                "/v1/messages",
                "/v1/messages/count_tokens",
                "/v1/models",
                "/v1/models/{id}",
            ],
            UpstreamId::Openai => &[
                "/v1/responses",
                "/v1/chat/completions",
                "/v1/models",
                "/v1/models/{id}",
            ],
            UpstreamId::OpenaiCodex => &["/responses", "/models"],
        }
    }
}

/// Request wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// Anthropic `/v1/messages`.
    Messages,
    /// OpenAI `/v1/responses`.
    Responses,
    /// OpenAI `/v1/chat/completions`.
    Chat,
}

/// A served endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// Anthropic messages.
    Messages,
    /// Anthropic token counting.
    CountTokens,
    /// OpenAI responses.
    Responses,
    /// OpenAI chat completions.
    ChatCompletions,
    /// Model list.
    Models,
    /// One model.
    Model,
}

impl Endpoint {
    /// The wire format of a sanitized `POST`; `None` for model lists.
    pub fn wire(self) -> Option<Wire> {
        match self {
            Endpoint::Messages | Endpoint::CountTokens => Some(Wire::Messages),
            Endpoint::Responses => Some(Wire::Responses),
            Endpoint::ChatCompletions => Some(Wire::Chat),
            Endpoint::Models | Endpoint::Model => None,
        }
    }
}

fn model_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':'))
        && s != "."
        && s != ".."
}

/// The endpoint for `method` and the path after the prefix; `None` = not served.
pub fn endpoint(up: UpstreamId, method: &Method, rest: &str) -> Option<Endpoint> {
    let post = *method == Method::POST;
    let get = *method == Method::GET;
    match (up, rest) {
        (UpstreamId::Anthropic, "/v1/messages") if post => Some(Endpoint::Messages),
        (UpstreamId::Anthropic, "/v1/messages/count_tokens") if post => Some(Endpoint::CountTokens),
        (UpstreamId::Openai, "/v1/responses") if post => Some(Endpoint::Responses),
        (UpstreamId::Openai, "/v1/chat/completions") if post => Some(Endpoint::ChatCompletions),
        (UpstreamId::OpenaiCodex, "/responses") if post => Some(Endpoint::Responses),
        (UpstreamId::Anthropic | UpstreamId::Openai, "/v1/models") if get => Some(Endpoint::Models),
        (UpstreamId::OpenaiCodex, "/models") if get => Some(Endpoint::Models),
        (UpstreamId::Anthropic | UpstreamId::Openai, r) if get => r
            .strip_prefix("/v1/models/")
            .filter(|m| model_id(m))
            .map(|_| Endpoint::Model),
        _ => None,
    }
}

/// Only the query strings harnesses are recorded to send (spec §4).
pub fn query_allowed(up: UpstreamId, ep: Endpoint, query: Option<&str>) -> bool {
    let Some(q) = query else { return true };
    match (up, ep) {
        (UpstreamId::Anthropic, Endpoint::Messages | Endpoint::CountTokens) => q == "beta=true",
        (UpstreamId::OpenaiCodex, Endpoint::Models) => {
            q.strip_prefix("client_version=").is_some_and(|v| {
                (1..=32).contains(&v.len())
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
            })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn served_endpoints_and_queries() {
        use Endpoint::*;
        use UpstreamId::*;
        assert_eq!(
            endpoint(Anthropic, &Method::POST, "/v1/messages"),
            Some(Messages)
        );
        assert_eq!(
            endpoint(Anthropic, &Method::POST, "/v1/messages/count_tokens"),
            Some(CountTokens)
        );
        assert_eq!(
            endpoint(Anthropic, &Method::GET, "/v1/models/claude-x"),
            Some(Model)
        );
        assert_eq!(
            endpoint(Anthropic, &Method::POST, "/v1/messages/batches"),
            None
        );
        assert_eq!(
            endpoint(Openai, &Method::POST, "/v1/responses"),
            Some(Responses)
        );
        assert_eq!(
            endpoint(Openai, &Method::POST, "/v1/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(endpoint(Openai, &Method::POST, "/v1/files"), None);
        assert_eq!(
            endpoint(OpenaiCodex, &Method::POST, "/responses"),
            Some(Responses)
        );
        assert_eq!(
            endpoint(OpenaiCodex, &Method::POST, "/responses/compact"),
            None
        );
        assert_eq!(endpoint(Anthropic, &Method::GET, "/v1/models/../x"), None);
        assert!(query_allowed(Anthropic, Messages, Some("beta=true")));
        assert!(query_allowed(Anthropic, Messages, None));
        assert!(!query_allowed(Anthropic, Messages, Some("beta=true&x=1")));
        assert!(query_allowed(
            OpenaiCodex,
            Models,
            Some("client_version=0.47.0")
        ));
        assert!(!query_allowed(Openai, Responses, Some("a=b")));
    }
}
