//! Tests for [`matrix_sdk::Client::subscribe_to_to_device_messages`].

use assert_matches2::assert_let;
use matrix_sdk::test_utils::mocks::MatrixMockServer;
use matrix_sdk_test::async_test;
use serde_json::json;
use tokio::sync::broadcast::error::TryRecvError;

#[async_test]
async fn test_subscribe_to_to_device_messages() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let (_drop_guard, mut subscriber) =
        client.subscribe_to_to_device_messages(vec!["m.custom.wanted".to_owned()]);

    server
        .mock_sync()
        .ok_and_run(&client, |builder| {
            builder.add_to_device_event(json!({
                "sender": "@alice:example.com",
                "type": "m.custom.wanted",
                "content": { "a": "test" },
            }));
        })
        .await;

    assert_let!(Ok(message) = subscriber.try_recv());
    assert_eq!(message.raw.get_field::<String>("type").unwrap().unwrap(), "m.custom.wanted");
    // It was sent in the clear.
    assert!(message.encryption_info.is_none());

    assert_eq!(subscriber.try_recv().unwrap_err(), TryRecvError::Empty);
}

#[async_test]
async fn test_subscribe_to_to_device_messages_filters_by_type() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let (_drop_guard, mut subscriber) =
        client.subscribe_to_to_device_messages(vec!["m.custom.wanted".to_owned()]);

    server
        .mock_sync()
        .ok_and_run(&client, |builder| {
            builder
                .add_to_device_event(json!({
                    "sender": "@alice:example.com",
                    "type": "m.custom.unwanted",
                    "content": { "a": "test" },
                }))
                .add_to_device_event(json!({
                    "sender": "@alice:example.com",
                    "type": "m.custom.wanted",
                    "content": { "b": "test" },
                }));
        })
        .await;

    // Only the subscribed type made it through.
    assert_let!(Ok(message) = subscriber.try_recv());
    assert_eq!(message.raw.get_field::<String>("type").unwrap().unwrap(), "m.custom.wanted");

    assert_eq!(subscriber.try_recv().unwrap_err(), TryRecvError::Empty);
}

#[async_test]
async fn test_subscribe_to_to_device_messages_stops_on_drop() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let (drop_guard, mut subscriber) =
        client.subscribe_to_to_device_messages(vec!["m.custom.wanted".to_owned()]);

    // Dropping the guard deregisters the underlying event handler, which drops
    // the sender and so closes the channel. Consumers rely on seeing `Closed`
    // to know they can stop listening.
    drop(drop_guard);

    server
        .mock_sync()
        .ok_and_run(&client, |builder| {
            builder.add_to_device_event(json!({
                "sender": "@alice:example.com",
                "type": "m.custom.wanted",
                "content": { "a": "test" },
            }));
        })
        .await;

    assert_eq!(subscriber.try_recv().unwrap_err(), TryRecvError::Closed);
}

#[async_test]
async fn test_subscribe_to_to_device_messages_empty_filter_never_fires() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let (_drop_guard, mut subscriber) = client.subscribe_to_to_device_messages(vec![]);

    server
        .mock_sync()
        .ok_and_run(&client, |builder| {
            builder.add_to_device_event(json!({
                "sender": "@alice:example.com",
                "type": "m.custom.wanted",
                "content": { "a": "test" },
            }));
        })
        .await;

    assert_eq!(subscriber.try_recv().unwrap_err(), TryRecvError::Empty);
}
