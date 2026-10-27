//! M5 spec §10, §16.1 item 8: at TRACE, behind the daemon's own privacy
//! filter, adding, rescanning, and removing a folder, an outbox run, and
//! failures leave no fixture name, path component, slug, or token in the log
//! or in an error body. The subscriber is process-wide (the mirror's worker
//! and poller threads must be captured; a thread-local `set_default` would
//! miss them), so this binary holds this one test.

mod common;

use std::time::{Duration, Instant};

use common::Capture;
use common::mirror::start_mirror;
use inumaki_client::{Client, Method as M};
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

async fn raw(c: &Client, m: M, p: &str, body: Value) -> (u16, Vec<u8>) {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let r = c.raw(m, p, bytes).await.unwrap();
    (r.status, r.body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_path_or_name_reaches_the_log_or_an_error_body() {
    let cap = Capture::new();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    let m = start_mirror().await;
    let c = Client::new(&m.d.socket);
    let mut error_bodies: Vec<String> = Vec::new();
    let mut note = |r: (u16, Vec<u8>)| {
        if r.0 >= 400 {
            error_bodies.push(String::from_utf8_lossy(&r.1).into_owned());
        }
        r.0
    };
    let akten = "/v1/datasets/qwxzvk-akten/folder";
    note(
        raw(
            &c,
            M::POST,
            "/v1/datasets",
            json!({"id": "qwxzvk-akten", "name": "Akten", "kind": "folder"}),
        )
        .await,
    );
    note(
        raw(
            &c,
            M::POST,
            "/v1/datasets",
            json!({"id": "qwxzvk-mail", "name": "Mail"}),
        )
        .await,
    );
    let src = m.base.join("Kunde Zyxwuria Quolnath");
    std::fs::create_dir_all(src.join("Quolnath GmbH")).unwrap();
    std::fs::write(
        src.join("Quolnath GmbH/Angebot Zyxwuria.txt"),
        "Zyxwuria Quolnath\n",
    )
    .unwrap();
    std::fs::write(src.join("gross.txt"), vec![b'a'; 2 * 1024 * 1024]).unwrap();
    let not_a_dir = m.base.join("Zyxwuria.txt");
    std::fs::write(&not_a_dir, "x").unwrap();
    // Refusals that carry name-bearing paths, against the real dataset
    // (before it has a folder, so validation runs).
    assert_eq!(
        note(raw(&c, M::POST, akten, json!({"source": src.join("missing")})).await),
        400
    );
    assert_eq!(
        note(
            raw(
                &c,
                M::POST,
                akten,
                json!({"source": src, "outbox_destination": not_a_dir})
            )
            .await
        ),
        400
    );
    assert_eq!(
        note(raw(&c, M::POST, akten, json!({"source": src, "x": 1})).await),
        400
    );
    assert_eq!(
        note(
            raw(
                &c,
                M::POST,
                "/v1/datasets/qwxzvk-mail/folder",
                json!({"source": src})
            )
            .await
        ),
        400
    );
    assert_eq!(
        note(
            raw(
                &c,
                M::POST,
                "/v1/datasets/qwxzvk-zwei/folder",
                json!({"source": src})
            )
            .await
        ),
        404
    );
    assert_eq!(
        note(raw(&c, M::POST, akten, json!({"source": src})).await),
        201
    );
    assert_eq!(
        note(raw(&c, M::POST, akten, json!({"source": src})).await),
        409
    );
    assert_eq!(
        note(raw(&c, M::GET, "/v1/datasets/qwxzvk-mail/folder", Value::Null).await),
        404
    );

    // The scan and the outbox run really happened (not a vacuous pass): wait
    // for a mirrored file and a placeholder for the oversized one.
    let status = |c: Client| async move {
        let (code, b) = raw(&c, M::GET, "/v1/folders", Value::Null).await;
        assert_eq!(code, 200);
        serde_json::from_slice::<Value>(&b).unwrap()["folders"][0].clone()
    };
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let f = status(c.clone()).await;
        let n = |k: &str| f["files"][k].as_u64().unwrap();
        if n("mirrored") >= 1 && n("blocked") + n("unsupported") >= 1 {
            break;
        }
        assert!(
            Instant::now() < until,
            "the scan did not finish within 30 s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // A reply with an unknown token is refused: the outbox run happened.
    let out = m
        .root
        .join(m.d.state.vault.opaque_id("qwxzvk-akten"))
        .join("outbox");
    std::fs::write(out.join("reply Zyxwuria.txt"), "<PERSON_ffffff>\n").unwrap();
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let f = status(c.clone()).await;
        if f["outbox_files"]["with_unresolved"].as_u64().unwrap() >= 1 {
            break;
        }
        assert!(
            Instant::now() < until,
            "the outbox run did not happen within 30 s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        note(raw(&c, M::POST, &format!("{akten}/rescan"), Value::Null).await),
        202
    );
    assert_eq!(note(raw(&c, M::GET, "/v1/folders", Value::Null).await), 200);
    assert_eq!(note(raw(&c, M::DELETE, akten, Value::Null).await), 204);
    assert_eq!(note(raw(&c, M::DELETE, akten, Value::Null).await), 404);
    let log = cap.text();
    assert!(log.contains("access"), "the capture is live");
    let base = m.base.file_name().unwrap().to_string_lossy().into_owned();
    for needle in [
        "Zyxwuria",
        "Quolnath",
        "Kunde",
        "qwxzvk",
        "Angebot",
        "reply",
        "PERSON_ffffff",
        "gross",
        base.as_str(),
    ] {
        assert!(!log.contains(needle), "{needle} in the log");
        for b in &error_bodies {
            assert!(!b.contains(needle), "{needle} in an error body");
        }
    }
}
