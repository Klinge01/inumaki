//! The per-dataset catalog (M4 spec §5.2): the already sanitized tools,
//! prompts, resources (exposed handles), and templates of every configured
//! upstream in creation order (a stopped one with its last-known lists);
//! later collisions prefixed `<upstream>__<name>`; a stable map from
//! exposed name or handle to (upstream index, original name or URI).

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use tokio::time::Instant;

use rmcp::model::{PaginatedRequestParams, Prompt, Resource, ResourceTemplate, Tool};
use rmcp::{Peer, RoleClient};

use crate::handles::{RES_PREFIX, TPL_PREFIX, split_handle};

/// True for `[A-Za-z0-9_.-]{1,64}`: the only tool and prompt names, and
/// schema property names, the gateway exposes (M4 spec §5.2).
pub fn valid_static_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// An upstream's raw lists, before discovery sanitization. `Debug` prints counts.
#[derive(Clone, Default)]
pub struct RawLists {
    /// Tools.
    pub tools: Vec<Tool>,
    /// Prompts.
    pub prompts: Vec<Prompt>,
    /// Resources.
    pub resources: Vec<Resource>,
    /// Resource templates.
    pub templates: Vec<ResourceTemplate>,
}

impl std::fmt::Debug for RawLists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawLists")
            .field("tools", &self.tools.len())
            .field("prompts", &self.prompts.len())
            .field("resources", &self.resources.len())
            .field("templates", &self.templates.len())
            .finish()
    }
}

/// Where an exposed template routes to. `Debug` prints lengths.
#[derive(Clone, PartialEq, Eq)]
pub struct TemplateRoute {
    /// The upstream's template.
    pub original: String,
    /// Parameter names in exposure order.
    pub params: Vec<String>,
}

impl std::fmt::Debug for TemplateRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplateRoute")
            .field("len", &self.original.len())
            .field("params", &self.params.len())
            .finish()
    }
}

/// One upstream's sanitized lists. `Debug` prints the name, index, and counts.
#[derive(Clone)]
pub struct UpstreamLists {
    /// Upstream name.
    pub name: String,
    /// Position in the dataset's upstream vector.
    pub index: usize,
    /// Tools (names and schemas reviewed, metadata sanitized).
    pub tools: Vec<Tool>,
    /// Prompts.
    pub prompts: Vec<Prompt>,
    /// Resources with exposed handle URIs, paired with the original URI.
    pub resources: Vec<(Resource, String)>,
    /// Templates with exposed handle templates, paired with their route.
    pub templates: Vec<(ResourceTemplate, TemplateRoute)>,
}

impl std::fmt::Debug for UpstreamLists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamLists")
            .field("name", &self.name)
            .field("index", &self.index)
            .field("tools", &self.tools.len())
            .field("prompts", &self.prompts.len())
            .field("resources", &self.resources.len())
            .field("templates", &self.templates.len())
            .finish()
    }
}

/// Most pages fetched per list: rmcp's `list_all_*` follows `next_cursor`
/// without a bound, so a hostile or broken upstream could keep the gateway
/// listing forever.
pub const MAX_LIST_PAGES: usize = 64;

/// Why an upstream's lists could not be fetched. Classes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    /// A list call exceeded the call timeout.
    #[error("listing timed out")]
    Timeout,
    /// A list had more than [`MAX_LIST_PAGES`] pages.
    #[error("listing exceeded the page limit")]
    TooManyPages,
    /// The transport failed or the answer was not a list.
    #[error("listing failed")]
    Failed,
}

/// One list, page by page, all pages before `deadline`, at most
/// [`MAX_LIST_PAGES`] pages. An MCP error (the upstream does not offer the
/// list) is an empty list; anything else fails the listing, so a transient
/// transport error never looks like an upstream that lists nothing (which
/// the first listing would bind as its reviewed schema).
async fn paged<T, F, Fut>(deadline: Instant, mut page: F) -> Result<Vec<T>, ListError>
where
    F: FnMut(Option<PaginatedRequestParams>) -> Fut,
    Fut: std::future::Future<Output = Result<(Vec<T>, Option<String>), rmcp::ServiceError>>,
{
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_LIST_PAGES {
        let params = cursor
            .take()
            .map(|c| PaginatedRequestParams::default().with_cursor(Some(c)));
        match tokio::time::timeout_at(deadline, page(params)).await {
            Err(_) => return Err(ListError::Timeout),
            Ok(Err(rmcp::ServiceError::McpError(_))) if out.is_empty() => return Ok(Vec::new()),
            Ok(Err(_)) => return Err(ListError::Failed),
            Ok(Ok((items, next))) => {
                out.extend(items);
                match next {
                    Some(c) => cursor = Some(c),
                    None => return Ok(out),
                }
            }
        }
    }
    Err(ListError::TooManyPages)
}

/// Ask an upstream for every list it announced in its capabilities (one
/// it did not announce is empty). The whole listing (every list, every
/// page) must finish within `timeout`, and each list has at most
/// [`MAX_LIST_PAGES`] pages; see [`ListError`].
pub async fn fetch_lists(
    peer: &Peer<RoleClient>,
    timeout: Duration,
) -> Result<RawLists, ListError> {
    let caps = peer.peer_info().map(|i| i.capabilities.clone());
    // No server info (never happens after a handshake): ask for everything.
    let (tools, prompts, resources) = caps.as_ref().map_or((true, true, true), |c| {
        (
            c.tools.is_some(),
            c.prompts.is_some(),
            c.resources.is_some(),
        )
    });
    let deadline = Instant::now() + timeout;
    let mut raw = RawLists::default();
    if tools {
        raw.tools = paged(deadline, |p| async move {
            peer.list_tools(p).await.map(|r| (r.tools, r.next_cursor))
        })
        .await?;
    }
    if prompts {
        raw.prompts = paged(deadline, |p| async move {
            peer.list_prompts(p)
                .await
                .map(|r| (r.prompts, r.next_cursor))
        })
        .await?;
    }
    if resources {
        raw.resources = paged(deadline, |p| async move {
            peer.list_resources(p)
                .await
                .map(|r| (r.resources, r.next_cursor))
        })
        .await?;
        raw.templates = paged(deadline, |p| async move {
            peer.list_resource_templates(p)
                .await
                .map(|r| (r.resource_templates, r.next_cursor))
        })
        .await?;
    }
    Ok(raw)
}

/// `<upstream>__<name>`.
pub fn prefixed(upstream: &str, name: &str) -> String {
    format!("{upstream}__{name}")
}

/// `original` when free, else `<upstream>__<original>` when that is free;
/// `None` when both are taken (an upstream that lists `x` after
/// `<itself>__x`), so an exposed name never routes to two things, or when
/// the name to expose is not a [`valid_static_name`] (a prefixed name can
/// exceed 64 bytes).
fn exposed_name(
    routes: &HashMap<String, (usize, String)>,
    upstream: &str,
    original: &str,
) -> Option<String> {
    let name = if routes.contains_key(original) {
        prefixed(upstream, original)
    } else {
        original.to_string()
    };
    (valid_static_name(&name) && !routes.contains_key(&name)).then_some(name)
}

/// The merged lists and the routes back to each upstream. `Debug` prints
/// counts and upstream names.
#[derive(Clone, Default)]
pub struct Catalog {
    tools: Vec<Tool>,
    prompts: Vec<Prompt>,
    resources: Vec<Resource>,
    templates: Vec<ResourceTemplate>,
    tool_routes: HashMap<String, (usize, String)>,
    prompt_routes: HashMap<String, (usize, String)>,
    resource_routes: HashMap<String, (usize, String)>,
    template_routes: HashMap<String, (usize, TemplateRoute)>,
    upstream_names: Vec<String>,
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Catalog")
            .field("upstreams", &self.upstream_names)
            .field("tools", &self.tools.len())
            .field("prompts", &self.prompts.len())
            .field("resources", &self.resources.len())
            .field("templates", &self.templates.len())
            .finish()
    }
}

impl Catalog {
    /// No upstreams.
    pub fn empty() -> Catalog {
        Catalog::default()
    }

    /// Merge `lists`: one entry per configured upstream, in creation order
    /// (M4 spec §5: the later upstream's item is prefixed). An upstream that
    /// is down contributes its last-known lists
    /// ([`crate::UpstreamHandle::last_lists`]) so its names keep their owner
    /// and route to it (calls then answer `upstream_unavailable`); leaving it
    /// out would hand a colliding name to another upstream, which would then
    /// receive arguments rehydrated for the first.
    ///
    /// Fails closed item by item, with a class-only warning: a name that is
    /// taken even after prefixing or is not a static name, a resource whose
    /// URI is not a well-formed `inumaki://res/` handle, a template whose URI
    /// is not a well-formed `inumaki://tpl/` handle, and a handle listed
    /// twice are not exposed.
    pub fn build(lists: &[UpstreamLists]) -> Catalog {
        let mut c = Catalog::default();
        for l in lists {
            while c.upstream_names.len() <= l.index {
                c.upstream_names.push(String::new());
            }
            c.upstream_names[l.index] = l.name.clone();
            for t in &l.tools {
                let original = t.name.to_string();
                let Some(exposed) = exposed_name(&c.tool_routes, &l.name, &original) else {
                    tracing::warn!(upstream = %l.name, what = "tool", "name collides after prefixing; not exposed");
                    continue;
                };
                let mut tool = t.clone();
                tool.name = Cow::Owned(exposed.clone());
                c.tool_routes.insert(exposed, (l.index, original));
                c.tools.push(tool);
            }
            for p in &l.prompts {
                let original = p.name.clone();
                let Some(exposed) = exposed_name(&c.prompt_routes, &l.name, &original) else {
                    tracing::warn!(upstream = %l.name, what = "prompt", "name collides after prefixing; not exposed");
                    continue;
                };
                let mut prompt = p.clone();
                prompt.name = exposed.clone();
                c.prompt_routes.insert(exposed, (l.index, original));
                c.prompts.push(prompt);
            }
            for (r, original) in &l.resources {
                let well_formed = matches!(split_handle(&r.uri, RES_PREFIX), Some((_, None)));
                if !well_formed || c.resource_routes.contains_key(&r.uri) {
                    tracing::warn!(upstream = %l.name, what = "resource", well_formed, "not a fresh resource handle; not exposed");
                    continue;
                }
                c.resource_routes
                    .insert(r.uri.clone(), (l.index, original.clone()));
                c.resources.push(r.clone());
            }
            for (t, route) in &l.templates {
                let base = split_handle(&t.uri_template, TPL_PREFIX).map(|(b, _)| b.to_string());
                let Some(base) = base.filter(|b| !c.template_routes.contains_key(b)) else {
                    tracing::warn!(upstream = %l.name, what = "template", "not a fresh template handle; not exposed");
                    continue;
                };
                c.template_routes.insert(base, (l.index, route.clone()));
                c.templates.push(t.clone());
            }
        }
        c
    }

    /// Exposed tools.
    pub fn tools(&self) -> &[Tool] {
        &self.tools
    }

    /// Exposed prompts.
    pub fn prompts(&self) -> &[Prompt] {
        &self.prompts
    }

    /// Exposed resources.
    pub fn resources(&self) -> &[Resource] {
        &self.resources
    }

    /// Exposed templates.
    pub fn templates(&self) -> &[ResourceTemplate] {
        &self.templates
    }

    /// Upstream index and original tool name for an exposed name.
    pub fn route_tool(&self, exposed: &str) -> Option<(usize, &str)> {
        self.tool_routes.get(exposed).map(|(i, n)| (*i, n.as_str()))
    }

    /// Upstream index and original prompt name for an exposed name.
    pub fn route_prompt(&self, exposed: &str) -> Option<(usize, &str)> {
        self.prompt_routes
            .get(exposed)
            .map(|(i, n)| (*i, n.as_str()))
    }

    /// Upstream index and original URI for an exposed handle.
    pub fn route_resource(&self, exposed: &str) -> Option<(usize, &str)> {
        self.resource_routes
            .get(exposed)
            .map(|(i, u)| (*i, u.as_str()))
    }

    /// Upstream index, route, and the parameter values of an exposed
    /// template URI (`inumaki://tpl/<h>/v1/v2…`); `None` when the handle is
    /// unknown or the value count differs from the parameter count.
    pub fn route_template(&self, exposed: &str) -> Option<(usize, &TemplateRoute, Vec<String>)> {
        let (base, rest) = split_handle(exposed, TPL_PREFIX)?;
        let (i, route) = self.template_routes.get(base)?;
        let values: Vec<String> = match rest {
            Some(r) if !r.is_empty() => r.split('/').map(str::to_string).collect(),
            _ => Vec::new(),
        };
        if values.len() != route.params.len() {
            return None;
        }
        Some((*i, route, values))
    }

    /// Whether any upstream offers tools, prompts, resources.
    pub fn offers(&self) -> (bool, bool, bool) {
        (
            !self.tools.is_empty(),
            !self.prompts.is_empty(),
            !self.resources.is_empty() || !self.templates.is_empty(),
        )
    }

    /// Name of the upstream at `index` (empty when unknown).
    pub fn upstream_name(&self, index: usize) -> &str {
        self.upstream_names.get(index).map_or("", String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page_of(
        n: usize,
        next: Option<&str>,
    ) -> Result<(Vec<usize>, Option<String>), rmcp::ServiceError> {
        Ok((vec![n], next.map(str::to_string)))
    }

    #[tokio::test(start_paused = true)]
    async fn an_endless_cursor_stops_at_the_page_cap() {
        let mut calls = 0usize;
        let r = paged(Instant::now() + Duration::from_secs(60), |_| {
            calls += 1;
            let n = calls;
            async move { page_of(n, Some("again")) }
        })
        .await;
        assert_eq!(r, Err(ListError::TooManyPages));
        assert_eq!(calls, MAX_LIST_PAGES);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_covers_every_page() {
        // Each page answers in 400 ms; a 1 s deadline allows two of them,
        // not 64 x 1 s.
        let t0 = Instant::now();
        let r: Result<Vec<usize>, _> = paged(t0 + Duration::from_secs(1), |_| async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            page_of(1, Some("more"))
        })
        .await;
        assert_eq!(r, Err(ListError::Timeout));
        assert!(
            t0.elapsed() <= Duration::from_millis(1_050),
            "{:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn pages_are_joined_and_a_first_mcp_error_is_an_empty_list() {
        let mut calls = 0usize;
        let r = paged(Instant::now() + Duration::from_secs(5), |p| {
            calls += 1;
            let n = calls;
            async move {
                assert_eq!(p.is_some(), n > 1, "the cursor is passed on");
                page_of(n, (n < 3).then_some("c"))
            }
        })
        .await;
        assert_eq!(r, Ok(vec![1, 2, 3]));
        let r: Result<Vec<usize>, _> = paged(Instant::now() + Duration::from_secs(5), |_| async {
            Err(rmcp::ServiceError::McpError(
                rmcp::model::ErrorData::method_not_found::<rmcp::model::ListToolsRequestMethod>(),
            ))
        })
        .await;
        assert_eq!(r, Ok(vec![]));
    }
}
