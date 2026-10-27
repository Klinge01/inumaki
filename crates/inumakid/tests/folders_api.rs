//! M5 spec §12: the folders endpoints answer the client types byte for
//! byte, every 400 message is the literal of §12.3, 409 and 404s as
//! specified, and the routes are absent from the TCP router. The log test
//! is `folders_log.rs` (it needs the process-wide subscriber).

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::mirror::start_mirror;
use inumaki_client::contract::assert_bytes_round_trip;
use inumaki_client::{Client, FolderBody, FoldersBody, Method as M, RescanBody};
use inumakid::check::Internal;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn raw(c: &Client, m: M, p: &str, body: Value) -> (u16, Vec<u8>) {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let r = c.raw(m, p, bytes).await.unwrap();
    (r.status, r.body)
}

fn message(b: &[u8]) -> String {
    serde_json::from_slice::<Value>(b).unwrap()["error"]["message"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn folder_bodies_match_the_client_types_and_errors_are_literal() {
    let m = start_mirror().await;
    let c = Client::new(&m.d.socket);
    let made = |code: u16| assert_eq!(code, 201);
    made(
        raw(
            &c,
            M::POST,
            "/v1/datasets",
            json!({"id": "qwxzvk-akten", "name": "Akten", "kind": "folder"}),
        )
        .await
        .0,
    );
    made(
        raw(
            &c,
            M::POST,
            "/v1/datasets",
            json!({"id": "qwxzvk-mail", "name": "M"}),
        )
        .await
        .0,
    );
    let src = m.base.join("Akten Zyxwuria");
    std::fs::create_dir_all(&src).unwrap();
    let file = m.base.join("a-file");
    std::fs::write(&file, "x").unwrap();
    let home = dirs::home_dir().unwrap();
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({"source": src, "extra": 1}),
            "unknown or invalid folder field",
        ),
        (json!({"source": 7}), "unknown or invalid folder field"),
        (
            json!({"source": "relative/path"}),
            "source must be an absolute path",
        ),
        (
            json!({"source": m.base.join("missing")}),
            "source must be an existing directory",
        ),
        (
            json!({"source": file}),
            "source must be an existing directory",
        ),
        (
            json!({"source": home}),
            "source must not be the home directory",
        ),
        (
            json!({"source": "/"}),
            "source must not contain the mirror root, the data directory, or the home directory",
        ),
        (
            json!({"source": m.root}),
            "source must not be inside the mirror root or the data directory",
        ),
        (
            json!({"source": src, "outbox_destination": "rel"}),
            "outbox_destination must be an absolute path",
        ),
        (
            json!({"source": src, "outbox_destination": m.root.join("x")}),
            "outbox_destination must not be inside the mirror root or the data directory",
        ),
        (
            json!({"source": src, "outbox_destination": file}),
            "outbox_destination must be a directory",
        ),
    ];
    for (body, msg) in cases {
        let (code, b) = raw(&c, M::POST, "/v1/datasets/qwxzvk-akten/folder", body).await;
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["error"]["type"], "bad_request");
        assert_eq!((code, message(&b).as_str()), (400, msg));
    }
    // A body that is not JSON at all.
    let (code, b) = {
        let r = c
            .raw(
                M::POST,
                "/v1/datasets/qwxzvk-akten/folder",
                b"not json".to_vec(),
            )
            .await
            .unwrap();
        (r.status, r.body)
    };
    assert_eq!(
        (code, message(&b).as_str()),
        (400, "unknown or invalid folder field")
    );

    let (code, b) = raw(
        &c,
        M::POST,
        "/v1/datasets/qwxzvk-mail/folder",
        json!({"source": src}),
    )
    .await;
    assert_eq!(
        (code, message(&b).as_str()),
        (400, "dataset kind must be folder")
    );
    let (code, b) = raw(
        &c,
        M::POST,
        "/v1/datasets/qwxzvk-akten/folder",
        json!({"source": src}),
    )
    .await;
    assert_eq!(code, 201);
    assert_bytes_round_trip::<FolderBody>(&b);
    let (code, b) = raw(
        &c,
        M::POST,
        "/v1/datasets/qwxzvk-akten/folder",
        json!({"source": src}),
    )
    .await;
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        (code, v["error"]["type"].as_str().unwrap()),
        (409, "conflict")
    );
    assert_eq!(
        message(&b),
        "a folder is already connected; delete it first"
    );
    // A connected dataset answers 409 whatever the new source is.
    let (code, b) = raw(
        &c,
        M::POST,
        "/v1/datasets/qwxzvk-akten/folder",
        json!({"source": "relative/path"}),
    )
    .await;
    assert_eq!(
        (code, message(&b).as_str()),
        (409, "a folder is already connected; delete it first")
    );
    let (code, b) = raw(
        &c,
        M::POST,
        "/v1/datasets/qwxzvk-other/folder",
        json!({"source": src}),
    )
    .await;
    assert_eq!((code, message(&b).as_str()), (404, "unknown dataset"));
    let inside = src.join("sub");
    std::fs::create_dir_all(&inside).unwrap();
    made(
        raw(
            &c,
            M::POST,
            "/v1/datasets",
            json!({"id": "qwxzvk-zwei", "name": "Z", "kind": "folder"}),
        )
        .await
        .0,
    );
    let (code, b) = raw(
        &c,
        M::POST,
        "/v1/datasets/qwxzvk-zwei/folder",
        json!({"source": inside}),
    )
    .await;
    assert_eq!(
        (code, message(&b).as_str()),
        (400, "source overlaps another folder dataset")
    );
    let (code, b) = raw(&c, M::GET, "/v1/datasets/qwxzvk-akten/folder", Value::Null).await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<FolderBody>(&b);
    let body: FolderBody = serde_json::from_slice(&b).unwrap();
    let (code, b) = raw(&c, M::GET, "/v1/folders", Value::Null).await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<FoldersBody>(&b);
    // The folder status names the same outbox destination as the folder body.
    let list: FoldersBody = serde_json::from_slice(&b).unwrap();
    let listed = list
        .folders
        .iter()
        .find(|f| f.dataset == "qwxzvk-akten")
        .unwrap();
    assert!(!body.outbox_destination.is_empty());
    assert_eq!(listed.outbox_destination, body.outbox_destination);
    let (code, b) = raw(
        &c,
        M::POST,
        "/v1/datasets/qwxzvk-akten/folder/rescan",
        Value::Null,
    )
    .await;
    assert_eq!(code, 202);
    assert_bytes_round_trip::<RescanBody>(&b);
    // A dataset without a folder: 404 on every route that needs one.
    for (method, path) in [
        (M::GET, "/v1/datasets/qwxzvk-zwei/folder"),
        (M::DELETE, "/v1/datasets/qwxzvk-zwei/folder"),
        (M::POST, "/v1/datasets/qwxzvk-zwei/folder/rescan"),
    ] {
        let (code, b) = raw(&c, method, path, Value::Null).await;
        assert_eq!((code, message(&b).as_str()), (404, "folder not configured"));
    }
    for (method, path) in [
        (M::GET, "/v1/datasets/qwxzvk-nirgends/folder"),
        (M::DELETE, "/v1/datasets/qwxzvk-nirgends/folder"),
        (M::POST, "/v1/datasets/qwxzvk-nirgends/folder/rescan"),
    ] {
        let (code, b) = raw(&c, method, path, Value::Null).await;
        assert_eq!((code, message(&b).as_str()), (404, "unknown dataset"));
    }
    assert_eq!(
        raw(
            &c,
            M::DELETE,
            "/v1/datasets/qwxzvk-akten/folder",
            Value::Null
        )
        .await
        .0,
        204
    );
    // Gone: a second delete is a 404, and the source is untouched.
    let (code, b) = raw(
        &c,
        M::DELETE,
        "/v1/datasets/qwxzvk-akten/folder",
        Value::Null,
    )
    .await;
    assert_eq!((code, message(&b).as_str()), (404, "folder not configured"));
    assert!(src.is_dir());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn folder_routes_are_absent_from_the_tcp_router() {
    let m = start_mirror().await;
    let addr = m.d.gateway_addr();
    for (method, p) in [
        ("GET", "/v1/folders"),
        ("GET", "/v1/datasets/x/folder"),
        ("POST", "/v1/datasets/x/folder"),
        ("DELETE", "/v1/datasets/x/folder"),
        ("POST", "/v1/datasets/x/folder/rescan"),
    ] {
        let app = inumakid::api::gateway::tcp_router(Arc::clone(&m.d.state), addr);
        let req = axum::http::Request::builder()
            .method(method)
            .uri(p)
            .header("host", addr.to_string())
            .body(axum::body::Body::empty())
            .unwrap();
        let r = app.oneshot(req).await.unwrap();
        assert_eq!(r.status(), 404, "{method} {p} must not be served on TCP");
    }
}

/// M6-3a's `check::mirror` drives these endpoints in process through
/// `api::router` with the `Internal` extension: a `check-<12 hex>-f` folder
/// dataset is refused from the socket, accepted in process, mirrors a file,
/// and is removed again through `DELETE …/folder`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_check_folder_dataset_works_through_the_internal_router() {
    let m = start_mirror().await;
    let call = |method: &str, path: String, body: Value| {
        let state = Arc::clone(&m.d.state);
        let method = method.to_string();
        async move {
            let mut req = axum::http::Request::builder()
                .method(method.as_str())
                .uri(path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(if body.is_null() {
                    String::new()
                } else {
                    body.to_string()
                }))
                .unwrap();
            req.extensions_mut().insert(Internal);
            let r = inumakid::api::router(state).oneshot(req).await.unwrap();
            let code = r.status().as_u16();
            (
                code,
                axum::body::to_bytes(r.into_body(), 1 << 20)
                    .await
                    .unwrap()
                    .to_vec(),
            )
        }
    };
    let id = "check-0123456789ab-f";
    let body = json!({"id": id, "name": "check", "kind": "folder", "profile": "offline"});
    // The socket refuses the reserved name; the internal call does not.
    let c = Client::new(&m.d.socket);
    assert_eq!(raw(&c, M::POST, "/v1/datasets", body.clone()).await.0, 400);
    assert_eq!(call("POST", "/v1/datasets".into(), body).await.0, 201);
    let source = m.base.join("check-source");
    let dest = m.base.join("check-outbox");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(
        source.join("record.txt"),
        "Zyxwuria Quolnath, AT61 1904 3002 3457 3201\n",
    )
    .unwrap();
    let (code, b) = call(
        "POST",
        format!("/v1/datasets/{id}/folder"),
        json!({"source": source.display().to_string(), "outbox_destination": dest.display().to_string()}),
    )
    .await;
    assert_eq!(code, 201);
    assert_bytes_round_trip::<FolderBody>(&b);
    let v: Value = serde_json::from_slice(&b).unwrap();
    let (mirror, outbox) = (
        std::path::PathBuf::from(v["mirror"].as_str().unwrap()),
        v["outbox"].as_str().unwrap().to_string(),
    );
    assert!(std::path::Path::new(&outbox).starts_with(&mirror));
    let until = Instant::now() + Duration::from_secs(30);
    let content = loop {
        let found = std::fs::read_dir(&mirror)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.') && e.path().is_file())
            .find_map(|e| std::fs::read_to_string(e.path()).ok());
        if let Some(t) = found {
            break t;
        }
        assert!(Instant::now() < until, "nothing mirrored within 30 s");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(!content.contains("3457 3201"), "the IBAN is in the mirror");
    assert_eq!(
        call("DELETE", format!("/v1/datasets/{id}/folder"), Value::Null)
            .await
            .0,
        204
    );
    assert!(
        !mirror.exists(),
        "the mirror tree is removed with the folder"
    );
    assert!(
        source.join("record.txt").is_file(),
        "the source is never touched"
    );
    assert_eq!(
        call("DELETE", format!("/v1/datasets/{id}"), Value::Null)
            .await
            .0,
        204
    );
}

/// M8 spec §9 / M5 spec §12.3 (amended): the proxy's reserved chat dataset
/// (and any `inumaki-` id) never carries a folder; the check comes before
/// the kind check and the message names no dataset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_folder_on_the_reserved_chat_dataset_is_refused() {
    let m = start_mirror().await;
    let c = Client::new(&m.d.socket);
    let src = m.base.join("Akten Zyxwuria");
    std::fs::create_dir_all(&src).unwrap();
    for id in ["inumaki-chat", "inumaki-other"] {
        let (code, b) = raw(
            &c,
            M::POST,
            &format!("/v1/datasets/{id}/folder"),
            json!({"source": src}),
        )
        .await;
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(code, 400, "{v}");
        assert_eq!(v["error"]["type"], "reserved", "{v}");
        assert_eq!(
            v["error"]["message"], "the chat dataset cannot be used here",
            "{v}"
        );
        assert!(!v.to_string().contains(id), "no slug in the error: {v}");
    }
    m.d.stop().await;
}
