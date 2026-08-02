//! Tests for the MSC4140 delayed-event API exposed on [`matrix_sdk::Room`].

use matrix_sdk::{
    ruma::{
        api::client::delayed_events::{DelayParameters, update_delayed_event::UpdateAction},
        events::{MessageLikeEventType, StateEventType},
    },
    test_utils::mocks::MatrixMockServer,
};
use matrix_sdk_test::async_test;
use ruma::{room_id, time::Duration};
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{body_json, method, path_regex},
};

#[async_test]
async fn test_send_delayed_raw() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    server.mock_room_state_encryption().plain().mount().await;
    let room = server.sync_joined_room(&client, room_id!("!a:b.c")).await;

    server
        .mock_room_send()
        .match_delayed_event(Duration::from_millis(1000))
        .for_type(MessageLikeEventType::RoomMessage)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "delay_id": "1234" })))
        .mock_once()
        .mount()
        .await;

    let response = room
        .send_delayed_raw(
            "m.room.message",
            json!({ "msgtype": "m.text", "body": "hello" }),
            DelayParameters::Timeout { timeout: Duration::from_millis(1000) },
        )
        .await
        .unwrap();

    assert_eq!(response.delay_id, "1234");
}

#[async_test]
async fn test_send_delayed_state_event_raw() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    server.mock_room_state_encryption().plain().mount().await;
    let room = server.sync_joined_room(&client, room_id!("!a:b.c")).await;

    server
        .mock_room_send_state()
        .match_delayed_event(Duration::from_millis(1000))
        .for_type(StateEventType::RoomTopic)
        .for_key("".to_owned())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "delay_id": "1234" })))
        .mock_once()
        .mount()
        .await;

    let response = room
        .send_delayed_state_event_raw(
            "m.room.topic",
            "",
            json!({ "topic": "hello" }),
            DelayParameters::Timeout { timeout: Duration::from_millis(1000) },
        )
        .await
        .unwrap();

    assert_eq!(response.delay_id, "1234");
}

#[async_test]
async fn test_update_delayed_event() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    server.mock_room_state_encryption().plain().mount().await;
    let room = server.sync_joined_room(&client, room_id!("!a:b.c")).await;

    for (action, serialized) in [
        (UpdateAction::Cancel, "cancel"),
        (UpdateAction::Restart, "restart"),
        (UpdateAction::Send, "send"),
    ] {
        let _guard = Mock::given(method("POST"))
            .and(path_regex(r"^/_matrix/client/unstable/org.matrix.msc4140/delayed_events/1234$"))
            .and(body_json(json!({ "action": serialized })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount_as_scoped(server.server())
            .await;

        room.update_delayed_event("1234".to_owned(), action).await.unwrap();
    }
}
