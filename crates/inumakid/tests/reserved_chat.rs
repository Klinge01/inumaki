//! M8 spec §9: `inumaki-` ids and kind `chat` are reserved.

mod common;

use hyper::Method;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_ids_and_the_chat_kind_are_refused() {
    let d = common::start().await;
    for body in [
        json!({ "id": "inumaki-chat", "name": "x" }),
        json!({ "id": "inumaki-x", "name": "x" }),
        json!({ "id": "kunden", "name": "x", "kind": "chat" }),
    ] {
        let (code, b) = d.call(Method::POST, "/v1/datasets", Some(body)).await;
        assert_eq!(code, 400, "{b}");
        assert_eq!(b["error"]["type"], "reserved", "{b}");
    }
    d.stop().await;
}
