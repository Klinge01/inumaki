//! One method per control-API route (M6 spec §9). Path parameters and query
//! values are percent-encoded. A 2xx answer decodes into the route's type;
//! anything else is `ClientError::Status`.

use hyper::Method;

use crate::client::{Client, ClientError, encode};
use crate::secret::Secret;
use crate::types::*;

const NONE: Option<&()> = None;

fn ds(id: &str, rest: &str) -> String {
    format!("/v1/datasets/{}{rest}", encode(id))
}

fn query(pairs: &[(&str, Option<String>)]) -> String {
    let parts: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", encode(v))))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

impl Client {
    // §9.2

    /// `GET /v1/status`.
    pub async fn status(&self) -> Result<StatusBody, ClientError> {
        self.json(Method::GET, "/v1/status", NONE).await
    }

    /// `GET /v1/datasets`.
    pub async fn datasets(&self) -> Result<Vec<DatasetBody>, ClientError> {
        self.json(Method::GET, "/v1/datasets", NONE).await
    }

    /// `POST /v1/datasets`.
    pub async fn create_dataset(&self, b: &CreateDataset) -> Result<DatasetBody, ClientError> {
        self.json(Method::POST, "/v1/datasets", Some(b)).await
    }

    /// `DELETE /v1/datasets/{id}`.
    pub async fn delete_dataset(&self, id: &str) -> Result<(), ClientError> {
        self.empty(Method::DELETE, &ds(id, ""), NONE).await
    }

    /// `POST /v1/datasets/{id}/rotate`.
    pub async fn rotate_dataset(&self, id: &str) -> Result<RotateBody, ClientError> {
        self.json(Method::POST, &ds(id, "/rotate"), NONE).await
    }

    /// `GET /v1/datasets/{id}/upstreams`.
    pub async fn upstreams(&self, id: &str) -> Result<Vec<UpstreamBody>, ClientError> {
        self.json(Method::GET, &ds(id, "/upstreams"), NONE).await
    }

    /// `POST /v1/datasets/{id}/upstreams`.
    pub async fn create_upstream(
        &self,
        id: &str,
        b: &UpstreamCreate,
    ) -> Result<UpstreamBody, ClientError> {
        self.json(Method::POST, &ds(id, "/upstreams"), Some(b))
            .await
    }

    /// `DELETE /v1/datasets/{id}/upstreams/{name}`.
    pub async fn delete_upstream(&self, id: &str, name: &str) -> Result<(), ClientError> {
        self.empty(
            Method::DELETE,
            &ds(id, &format!("/upstreams/{}", encode(name))),
            NONE,
        )
        .await
    }

    /// `POST /v1/datasets/{id}/upstreams/{name}/accept-schema`.
    pub async fn accept_schema(
        &self,
        id: &str,
        name: &str,
        fingerprint: Option<&str>,
    ) -> Result<(), ClientError> {
        let body = AcceptSchema {
            fingerprint: fingerprint.map(str::to_string),
        };
        self.empty(
            Method::POST,
            &ds(id, &format!("/upstreams/{}/accept-schema", encode(name))),
            Some(&body),
        )
        .await
    }

    /// `GET /v1/gateway/tokens`.
    pub async fn tokens(&self) -> Result<Vec<TokenBody>, ClientError> {
        self.json(Method::GET, "/v1/gateway/tokens", NONE).await
    }

    /// `POST /v1/gateway/tokens`.
    pub async fn create_token(&self, label: &str) -> Result<TokenCreated, ClientError> {
        let body = TokenCreate {
            label: label.to_string(),
        };
        self.json(Method::POST, "/v1/gateway/tokens", Some(&body))
            .await
    }

    /// `DELETE /v1/gateway/tokens/{id}`.
    pub async fn revoke_token(&self, id: i64) -> Result<(), ClientError> {
        self.empty(Method::DELETE, &format!("/v1/gateway/tokens/{id}"), NONE)
            .await
    }

    /// `GET /v1/activity?dataset=&since=&limit=`.
    pub async fn activity(&self, q: &ActivityQuery) -> Result<ActivityList, ClientError> {
        let qs = query(&[
            ("dataset", q.dataset.clone()),
            ("since", q.since.map(|v| v.to_string())),
            ("limit", q.limit.map(|v| v.to_string())),
        ]);
        self.json(Method::GET, &format!("/v1/activity{qs}"), NONE)
            .await
    }

    /// `GET /v1/activity/verify`.
    pub async fn verify_activity(&self) -> Result<ActivityVerify, ClientError> {
        self.json(Method::GET, "/v1/activity/verify", NONE).await
    }

    /// `POST /v1/inspect`.
    pub async fn inspect(&self, b: &InspectRequest) -> Result<InspectBody, ClientError> {
        self.json(Method::POST, "/v1/inspect", Some(b)).await
    }

    /// `POST /v1/sanitize`.
    pub async fn sanitize(&self, b: &SanitizeRequest) -> Result<SanitizeResponse, ClientError> {
        self.json(Method::POST, "/v1/sanitize", Some(b)).await
    }

    /// `POST /v1/rehydrate`.
    pub async fn rehydrate(&self, b: &RehydrateRequest) -> Result<RehydrateResponse, ClientError> {
        self.json(Method::POST, "/v1/rehydrate", Some(b)).await
    }

    /// `GET /v1/doctor`.
    pub async fn doctor(&self) -> Result<DoctorBody, ClientError> {
        self.json(Method::GET, "/v1/doctor", NONE).await
    }

    /// `POST /v1/shutdown`.
    pub async fn shutdown(&self) -> Result<ShutdownBody, ClientError> {
        self.json(Method::POST, "/v1/shutdown", NONE).await
    }

    // §9.3

    /// `GET /v1/datasets/{id}/journal?since=&limit=`.
    pub async fn journal(
        &self,
        id: &str,
        since: Option<i64>,
        limit: Option<u64>,
    ) -> Result<JournalList, ClientError> {
        let qs = query(&[
            ("since", since.map(|v| v.to_string())),
            ("limit", limit.map(|v| v.to_string())),
        ]);
        self.json(Method::GET, &ds(id, &format!("/journal{qs}")), NONE)
            .await
    }

    /// `GET /v1/datasets/{id}/journal/{record}?show_values=`.
    pub async fn journal_record(
        &self,
        id: &str,
        record: &str,
        show_values: bool,
    ) -> Result<JournalRecord, ClientError> {
        let path = ds(
            id,
            &format!("/journal/{}?show_values={show_values}", encode(record)),
        );
        self.json(Method::GET, &path, NONE).await
    }

    /// `GET /v1/datasets/{id}/entities?show_values=&limit=`.
    pub async fn entities(
        &self,
        id: &str,
        show_values: bool,
        limit: Option<u64>,
    ) -> Result<EntityList, ClientError> {
        let qs = query(&[
            ("show_values", Some(show_values.to_string())),
            ("limit", limit.map(|v| v.to_string())),
        ]);
        self.json(Method::GET, &ds(id, &format!("/entities{qs}")), NONE)
            .await
    }

    /// `DELETE /v1/datasets/{id}/entities/{token}`.
    pub async fn forget_token(&self, id: &str, token: &str) -> Result<ForgetBody, ClientError> {
        self.json(
            Method::DELETE,
            &ds(id, &format!("/entities/{}", encode(token))),
            NONE,
        )
        .await
    }

    /// `POST /v1/datasets/{id}/entities/forget`.
    pub async fn forget_value(&self, id: &str, value: &Secret) -> Result<ForgetBody, ClientError> {
        let body = ForgetRequest {
            value: value.clone(),
        };
        self.json(Method::POST, &ds(id, "/entities/forget"), Some(&body))
            .await
    }

    // §9.4

    /// `POST /v1/datasets/{id}/mailbox` (create or replace).
    pub async fn set_mailbox(
        &self,
        id: &str,
        b: &MailboxCreate,
    ) -> Result<MailboxBody, ClientError> {
        self.json(Method::POST, &ds(id, "/mailbox"), Some(b)).await
    }

    /// `GET /v1/datasets/{id}/mailbox`.
    pub async fn mailbox(&self, id: &str) -> Result<MailboxBody, ClientError> {
        self.json(Method::GET, &ds(id, "/mailbox"), NONE).await
    }

    /// `DELETE /v1/datasets/{id}/mailbox`.
    pub async fn delete_mailbox(&self, id: &str) -> Result<(), ClientError> {
        self.empty(Method::DELETE, &ds(id, "/mailbox"), NONE).await
    }

    /// `POST /v1/datasets/{id}/mailbox/check`.
    pub async fn check_mailbox(&self, id: &str) -> Result<MailboxCheck, ClientError> {
        self.json(Method::POST, &ds(id, "/mailbox/check"), NONE)
            .await
    }

    // §9.5

    /// `POST /v1/datasets/{id}/folder`.
    pub async fn set_folder(&self, id: &str, b: &FolderCreate) -> Result<FolderBody, ClientError> {
        self.json(Method::POST, &ds(id, "/folder"), Some(b)).await
    }

    /// `GET /v1/datasets/{id}/folder`.
    pub async fn folder(&self, id: &str) -> Result<FolderBody, ClientError> {
        self.json(Method::GET, &ds(id, "/folder"), NONE).await
    }

    /// `DELETE /v1/datasets/{id}/folder`.
    pub async fn delete_folder(&self, id: &str) -> Result<(), ClientError> {
        self.empty(Method::DELETE, &ds(id, "/folder"), NONE).await
    }

    /// `POST /v1/datasets/{id}/folder/rescan`.
    pub async fn rescan_folder(&self, id: &str) -> Result<RescanBody, ClientError> {
        self.json(Method::POST, &ds(id, "/folder/rescan"), NONE)
            .await
    }

    /// `GET /v1/folders`.
    pub async fn folders(&self) -> Result<FoldersBody, ClientError> {
        self.json(Method::GET, "/v1/folders", NONE).await
    }

    // §9.6

    /// `GET /v1/proxy`.
    pub async fn proxy(&self) -> Result<ProxyBody, ClientError> {
        self.json(Method::GET, "/v1/proxy", NONE).await
    }

    // §9.7

    /// `GET /v1/service`.
    pub async fn service(&self) -> Result<ServiceBody, ClientError> {
        self.json(Method::GET, "/v1/service", NONE).await
    }

    /// `POST /v1/models/pull` (202; `409` while a job runs).
    pub async fn start_models_pull(&self, b: &ModelsPull) -> Result<ModelsJob, ClientError> {
        self.json(Method::POST, "/v1/models/pull", Some(b)).await
    }

    /// `GET /v1/models/pull`.
    pub async fn models_pull(&self) -> Result<ModelsJob, ClientError> {
        self.json(Method::GET, "/v1/models/pull", NONE).await
    }

    /// `POST /v1/hook` (`451` is `ClientError::Status`).
    pub async fn hook(&self, b: &HookRequest) -> Result<HookResponse, ClientError> {
        self.json(Method::POST, "/v1/hook", Some(b)).await
    }

    /// `POST /v1/check` (`409` while a check is live).
    pub async fn create_check(&self, b: &CheckCreate) -> Result<CheckCreated, ClientError> {
        self.json(Method::POST, "/v1/check", Some(b)).await
    }

    /// `POST /v1/check/{id}/direct`.
    pub async fn check_direct(&self, id: &str) -> Result<CheckReport, ClientError> {
        self.json(
            Method::POST,
            &format!("/v1/check/{}/direct", encode(id)),
            NONE,
        )
        .await
    }

    /// `POST /v1/check/{id}/harness`.
    pub async fn check_harness(
        &self,
        id: &str,
        b: &CheckHarnessRequest,
    ) -> Result<CheckReport, ClientError> {
        self.json(
            Method::POST,
            &format!("/v1/check/{}/harness", encode(id)),
            Some(b),
        )
        .await
    }

    /// `GET /v1/check/{id}`.
    pub async fn check_report(&self, id: &str) -> Result<CheckReport, ClientError> {
        self.json(Method::GET, &format!("/v1/check/{}", encode(id)), NONE)
            .await
    }

    /// `DELETE /v1/check/{id}`.
    pub async fn delete_check(&self, id: &str) -> Result<(), ClientError> {
        self.empty(Method::DELETE, &format!("/v1/check/{}", encode(id)), NONE)
            .await
    }
}
