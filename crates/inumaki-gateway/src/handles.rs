//! Dataset-scoped opaque resource handles (M4 spec §5.2): raw upstream
//! URIs may contain identifiers, so the agent only ever sees
//! `inumaki://res/<16 hex>` and `inumaki://tpl/<16 hex>/{param}…`. Handles
//! are random, stable for the process lifetime, owned by one configured
//! upstream ([`Owner`]: its name plus the generation of its supervisor), and
//! dropped with it. A removed and re-added upstream of the same name is a
//! new owner, so an old handle never resolves on the new server.
//!
//! Every distinct URI an upstream lists or links in a result mints a
//! handle, so a store holds at most its cap ([`MAX_HANDLES`] by default):
//! past it, the oldest handle is forgotten and answers `unknown_resource`
//! like any stale handle, never another resource.

use std::collections::{HashMap, VecDeque};

/// Prefix of resource handles.
pub const RES_PREFIX: &str = "inumaki://res/";
/// Prefix of template handles.
pub const TPL_PREFIX: &str = "inumaki://tpl/";

/// `prefix` plus 16 random hex digits, not already a key of `taken`: a
/// handle must never be reassigned to a different resource.
fn fresh_handle<V>(prefix: &str, taken: &HashMap<String, V>) -> String {
    loop {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("OS randomness available");
        let h: String = std::iter::once(prefix.to_string())
            .chain(b.iter().map(|x| format!("{x:02x}")))
            .collect();
        if !taken.contains_key(&h) {
            return h;
        }
    }
}

/// One configured upstream for the process lifetime: its name and the
/// generation its supervisor was spawned with
/// ([`crate::UpstreamHandle::owner`]). Restarts keep the generation; a
/// removed and re-added upstream gets a new one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Owner {
    /// Upstream name.
    pub name: String,
    /// Process-unique supervisor generation.
    pub generation: u64,
}

impl Owner {
    /// An owner from its parts.
    pub fn new(name: impl Into<String>, generation: u64) -> Self {
        Owner {
            name: name.into(),
            generation,
        }
    }
}

/// Default cap on the handles one dataset's store holds.
pub const MAX_HANDLES: usize = 16_384;

/// The handle table of one dataset. `Debug` prints counts only.
pub struct HandleStore {
    /// handle → (owner, original uri)
    res: HashMap<String, (Owner, String)>,
    /// (owner, original uri) → handle
    res_rev: HashMap<(Owner, String), String>,
    /// handle → (owner, original template)
    tpl: HashMap<String, (Owner, String)>,
    tpl_rev: HashMap<(Owner, String), String>,
    /// Live handles, oldest first (eviction order).
    order: VecDeque<String>,
    cap: usize,
}

impl Default for HandleStore {
    fn default() -> Self {
        HandleStore::with_cap(MAX_HANDLES)
    }
}

impl std::fmt::Debug for HandleStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleStore")
            .field("resources", &self.res.len())
            .field("templates", &self.tpl.len())
            .field("cap", &self.cap)
            .finish()
    }
}

impl HandleStore {
    /// Empty, holding at most [`MAX_HANDLES`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty, holding at most `cap` handles (at least one).
    pub fn with_cap(cap: usize) -> Self {
        HandleStore {
            res: HashMap::new(),
            res_rev: HashMap::new(),
            tpl: HashMap::new(),
            tpl_rev: HashMap::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// Resource plus template handles held.
    pub fn len(&self) -> usize {
        self.res.len() + self.tpl.len()
    }

    /// True when no handle is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record a new handle and forget the oldest ones beyond the cap.
    fn remember(&mut self, handle: String) {
        self.order.push_back(handle);
        while self.len() > self.cap {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some(key) = self.res.remove(&old) {
                self.res_rev.remove(&key);
            } else if let Some(key) = self.tpl.remove(&old) {
                self.tpl_rev.remove(&key);
            }
        }
    }

    /// The exposed URI for `uri` of `owner`; minted once per pair.
    pub fn resource(&mut self, owner: &Owner, uri: &str) -> String {
        let key = (owner.clone(), uri.to_string());
        if let Some(h) = self.res_rev.get(&key) {
            return h.clone();
        }
        let h = fresh_handle(RES_PREFIX, &self.res);
        self.res.insert(h.clone(), key.clone());
        self.res_rev.insert(key, h.clone());
        self.remember(h.clone());
        h
    }

    /// The exposed template base (`inumaki://tpl/<h>`) for `template` of `owner`.
    pub fn template(&mut self, owner: &Owner, template: &str) -> String {
        let key = (owner.clone(), template.to_string());
        if let Some(h) = self.tpl_rev.get(&key) {
            return h.clone();
        }
        let h = fresh_handle(TPL_PREFIX, &self.tpl);
        self.tpl.insert(h.clone(), key.clone());
        self.tpl_rev.insert(key, h.clone());
        self.remember(h.clone());
        h
    }

    /// `(owner, original uri)` for an exposed resource URI.
    pub fn resolve_resource(&self, exposed: &str) -> Option<(&Owner, &str)> {
        self.res.get(exposed).map(|(u, o)| (u, o.as_str()))
    }

    /// `(owner, original template, rest)` for an exposed template URI,
    /// where `rest` is what follows the handle (`"42"` for `…/<h>/42`, `""`
    /// for the bare handle).
    pub fn resolve_template<'a>(
        &'a self,
        exposed: &'a str,
    ) -> Option<(&'a Owner, &'a str, &'a str)> {
        let body = exposed.strip_prefix(TPL_PREFIX)?;
        let (h, rest) = match body.find('/') {
            Some(i) => (&body[..i], &body[i + 1..]),
            None => (body, ""),
        };
        let key = format!("{TPL_PREFIX}{h}");
        self.tpl.get(&key).map(|(u, t)| (u, t.as_str(), rest))
    }

    /// Mint (here) the handles of `resources` and `templates` of `owner`
    /// and return a store holding just those, for a sanitization to run
    /// against without this store's lock: the engine batch that follows can
    /// take seconds, and resolving or retaining handles must never wait for
    /// it. [`HandleStore::absorb`] takes back anything minted meanwhile.
    pub fn scoped(&mut self, owner: &Owner, resources: &[&str], templates: &[&str]) -> HandleStore {
        let mut out = HandleStore::new();
        for uri in resources {
            let h = self.resource(owner, uri);
            let key = (owner.clone(), (*uri).to_string());
            out.res.insert(h.clone(), key.clone());
            out.res_rev.insert(key, h.clone());
            out.order.push_back(h);
        }
        for tpl in templates {
            let h = self.template(owner, tpl);
            let key = (owner.clone(), (*tpl).to_string());
            out.tpl.insert(h.clone(), key.clone());
            out.tpl_rev.insert(key, h.clone());
            out.order.push_back(h);
        }
        out
    }

    /// Take over handles a scoped store minted that this one lacks. A pair
    /// this store already maps keeps its own handle, and a handle id taken
    /// here for anything else is never reassigned (the scoped one then
    /// simply does not resolve).
    pub fn absorb(&mut self, other: HandleStore) {
        for (h, key) in other.res {
            if !self.res.contains_key(&h) && !self.res_rev.contains_key(&key) {
                self.res.insert(h.clone(), key.clone());
                self.res_rev.insert(key, h.clone());
                self.remember(h);
            }
        }
        for (h, key) in other.tpl {
            if !self.tpl.contains_key(&h) && !self.tpl_rev.contains_key(&key) {
                self.tpl.insert(h.clone(), key.clone());
                self.tpl_rev.insert(key, h.clone());
                self.remember(h);
            }
        }
    }

    /// Drop every handle whose owner is not in `configured`. Pass every
    /// configured upstream, running or not, so a restart keeps its handles
    /// and a removed upstream's handles go stale.
    pub fn retain(&mut self, configured: &[Owner]) {
        self.res.retain(|_, (u, _)| configured.contains(u));
        self.res_rev.retain(|(u, _), _| configured.contains(u));
        self.tpl.retain(|_, (u, _)| configured.contains(u));
        self.tpl_rev.retain(|(u, _), _| configured.contains(u));
        let (res, tpl) = (&self.res, &self.tpl);
        self.order
            .retain(|h| res.contains_key(h) || tpl.contains_key(h));
    }
}

/// The 16-hex-digit id of a well-formed handle: `exposed` must be `prefix`
/// followed by exactly 16 lowercase hex digits, then the end or `/`.
/// Returns the handle base (`prefix` + id) and what follows the `/`.
pub fn split_handle<'a>(exposed: &'a str, prefix: &str) -> Option<(&'a str, Option<&'a str>)> {
    let body = exposed.strip_prefix(prefix)?;
    let id = body.get(..16)?;
    if !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let base = &exposed[..prefix.len() + 16];
    match &body[16..] {
        "" => Some((base, None)),
        r => r.strip_prefix('/').map(|rest| (base, Some(rest))),
    }
}

/// Parameter names of an RFC 6570 level-1 template, in order.
pub fn template_params(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(i) = rest.find('{') {
        let Some(j) = rest[i..].find('}') else { break };
        out.push(rest[i + 1..i + j].to_string());
        rest = &rest[i + j + 1..];
    }
    out
}

/// Substitute `values` for `params` in `template`, in one pass, so a value
/// that itself looks like `{param}` is never expanded again. Values are
/// inserted as received (the agent percent-encodes per RFC 6570 simple
/// expansion). `None` when counts differ or the template names a
/// parameter that is not in `params`.
pub fn expand_template(template: &str, params: &[String], values: &[String]) -> Option<String> {
    if params.len() != values.len() {
        return None;
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(i) = rest.find('{') {
        let Some(j) = rest[i..].find('}') else { break };
        let name = &rest[i + 1..i + j];
        let k = params.iter().position(|p| p == name)?;
        out.push_str(&rest[..i]);
        out.push_str(&values[k]);
        rest = &rest[i + j + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_forgets_the_oldest_handle_which_never_resolves_again() {
        let a = Owner::new("a", 1);
        let mut s = HandleStore::with_cap(3);
        let first = s.resource(&a, "mem://1");
        let tpl = s.template(&a, "mem://t/{id}");
        let second = s.resource(&a, "mem://2");
        assert_eq!(s.len(), 3);
        assert_eq!(
            s.resource(&a, "mem://1"),
            first,
            "an existing pair mints nothing"
        );
        let third = s.resource(&a, "mem://3");
        assert_eq!(s.len(), 3, "bounded");
        assert!(
            s.resolve_resource(&first).is_none(),
            "the oldest went stale"
        );
        assert_eq!(
            s.resolve_template(&format!("{tpl}/x")).map(|t| t.1),
            Some("mem://t/{id}")
        );
        assert_eq!(s.resolve_resource(&second).map(|r| r.1), Some("mem://2"));
        assert_eq!(s.resolve_resource(&third).map(|r| r.1), Some("mem://3"));
        let again = s.resource(&a, "mem://1");
        assert_ne!(again, first, "a forgotten uri gets a fresh handle");
        assert!(s.resolve_resource(&first).is_none());
        assert!(
            s.resolve_template(&format!("{tpl}/x")).is_none(),
            "then the template"
        );
        s.retain(&[]);
        assert!(s.is_empty());
        assert!(s.order.is_empty(), "retain drops eviction entries too");
    }

    #[test]
    fn a_scoped_store_carries_its_handles_and_hands_new_ones_back() {
        let a = Owner::new("a", 1);
        let mut main = HandleStore::new();
        let known = main.resource(&a, "mem://known");
        let mut scoped = main.scoped(&a, &["mem://known", "mem://listed"], &["mem://t/{id}"]);
        assert_eq!(
            scoped.resource(&a, "mem://known"),
            known,
            "same handle as the main store"
        );
        let listed = scoped.resource(&a, "mem://listed");
        assert_eq!(
            main.resolve_resource(&listed).map(|r| r.1),
            Some("mem://listed"),
            "minted in main"
        );
        let late = scoped.resource(&a, "mem://late");
        assert!(main.resolve_resource(&late).is_none());
        // Meanwhile another request minted a different handle for the same pair.
        let other = main.resource(&a, "mem://late2");
        let mut second = HandleStore::new();
        let dup = second.resource(&a, "mem://late2");
        main.absorb(scoped);
        main.absorb(second);
        assert_eq!(
            main.resolve_resource(&late).map(|r| r.1),
            Some("mem://late")
        );
        assert!(
            main.resolve_resource(&dup).is_none(),
            "a mapped pair keeps its handle"
        );
        assert_eq!(
            main.resolve_resource(&other).map(|r| r.1),
            Some("mem://late2")
        );
    }
}
