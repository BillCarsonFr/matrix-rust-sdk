use matrix_sdk::test_utils::mocks::MatrixMockServer;
use matrix_sdk_test::{JoinedRoomBuilder, async_test, event_factory::EventFactory};
use ruma::{events::StateEventType, room_id, user_id};

#[async_test]
async fn test_subscribe_to_state_events() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let room_id = room_id!("!test:example.org");
    let room = server.sync_joined_room(&client, room_id).await;

    let (_drop_guard, mut subscriber) = room.subscribe_to_state_events(StateEventType::RoomTopic);

    let f = EventFactory::new().sender(user_id!("@alice:localhost"));

    // A state event of the subscribed type is forwarded when it arrives in the
    // state section of a sync, a state event of another type is not.
    server
        .sync_room(
            &client,
            JoinedRoomBuilder::new(room_id)
                .add_state_event(f.room_name("A room"))
                .add_state_event(f.room_topic("First topic")),
        )
        .await;

    let event = subscriber.recv().await.unwrap();
    assert_eq!(event.get_field::<String>("type").unwrap().unwrap(), "m.room.topic");

    // The state store was updated before we were called, so reacting to an event by
    // reading the state sees it.
    assert_eq!(room.topic().unwrap(), "First topic");

    // A state event arriving in the timeline is forwarded too.
    server
        .sync_room(
            &client,
            JoinedRoomBuilder::new(room_id).add_timeline_event(f.room_topic("Second topic")),
        )
        .await;

    let event = subscriber.recv().await.unwrap();
    assert_eq!(event.get_field::<String>("type").unwrap().unwrap(), "m.room.topic");
    assert_eq!(room.topic().unwrap(), "Second topic");

    // Nothing else was forwarded in between.
    assert!(subscriber.try_recv().is_err());
}

#[async_test]
async fn test_state_events_subscription_ends_with_the_drop_guard() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().build().await;

    let room_id = room_id!("!test:example.org");
    let room = server.sync_joined_room(&client, room_id).await;

    let (drop_guard, mut subscriber) = room.subscribe_to_state_events(StateEventType::RoomTopic);
    drop(drop_guard);

    let f = EventFactory::new().sender(user_id!("@alice:localhost"));
    server
        .sync_room(
            &client,
            JoinedRoomBuilder::new(room_id).add_state_event(f.room_topic("A topic")),
        )
        .await;

    assert!(subscriber.try_recv().is_err());
}
