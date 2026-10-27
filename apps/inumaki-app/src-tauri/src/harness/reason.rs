//! The adapters' `ReasonCode` as the app's fixed `Reason` (code and sentence).
//! The match is exhaustive and explicit: a new adapter code does not compile
//! until it has a code string here, and nothing is derived from `Debug`.

use inumaki_adapters::ReasonCode;

use super::ops::Reason;

/// The UI's stable code string for `r`.
pub fn code(r: ReasonCode) -> &'static str {
    use ReasonCode::*;
    match r {
        OpenclawSubscriptionBridge => "openclaw_subscription_bridge",
        CodexNoReadScope => "codex_no_read_scope",
        OpenclawDockerBindsOnly => "openclaw_docker_binds_only",
        OpenclawNoDockerSandbox => "openclaw_no_docker_sandbox",
        HermesFilesUnconfirmed => "hermes_files_unconfirmed",
        HermesOauthNoOverride => "hermes_oauth_no_override",
        CodexChatgptUnverified => "codex_chatgpt_unverified",
        ChatNotProtected => "chat_not_protected",
        RouteFailing => "route_failing",
        ChangedOutsideInumaki => "changed_outside_inumaki",
        NoFolderConnected => "no_folder_connected",
        NoTrafficYet => "no_traffic_yet",
        UpstreamNotRunning => "upstream_not_running",
        HookBinaryMissing => "hook_binary_missing",
        HookOutdated => "hook_outdated",
        HermesHooksFailOpen => "hermes_hooks_fail_open",
        OpenclawHookNotFiring => "openclaw_hook_not_firing",
        ProxyUnavailable => "proxy_unavailable",
        MirrorUnavailable => "mirror_unavailable",
        ServiceDown => "service_down",
        LoginUnknown => "login_unknown",
        ChatProviderNotRouted => "chat_provider_not_routed",
        CodexProfileOverride => "codex_profile_override",
        ChatTokensOnly => "chat_tokens_only",
        CodexHookNeedsTrust => "codex_hook_needs_trust",
    }
}

/// The code and the adapter's fixed sentence.
pub fn reason(r: ReasonCode) -> Reason {
    Reason {
        code: code(r),
        text: r.sentence(),
    }
}
