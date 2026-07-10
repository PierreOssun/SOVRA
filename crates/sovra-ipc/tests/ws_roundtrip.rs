use futures_util::{SinkExt, StreamExt};
use sl_mpc_mate::message::{AskMsg, InstanceId, MessageTag, MsgId, allocate_message};
use sovra_ipc::{
    client::WsRelay,
    hub::{RelayHub, ws_router},
};

async fn start_hub() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, ws_router(RelayHub::default()))
            .await
            .unwrap()
    });
    format!("ws://{addr}/ws")
}

fn test_frame() -> (MsgId, Vec<u8>) {
    let id = MsgId::new(
        &InstanceId::from([0u8; 32]),
        &[100],
        None,
        MessageTag::tag(0),
    );
    let frame = allocate_message(&id, 10, 0, &[1, 2, 3, 4, 5]);
    (id, frame)
}

#[tokio::test]
async fn publish_then_ask() {
    let url = start_hub().await;
    let (mut a, mut b) = (
        WsRelay::connect(&url).await.unwrap(),
        WsRelay::connect(&url).await.unwrap(),
    );
    let (id, frame) = test_frame();
    a.send(frame.clone()).await.unwrap();
    b.send(AskMsg::allocate(&id, 10)).await.unwrap();
    assert_eq!(b.next().await.unwrap(), frame);
}

#[tokio::test]
async fn ask_then_publish_wakes_waiter() {
    let url = start_hub().await;
    let (mut a, mut b) = (
        WsRelay::connect(&url).await.unwrap(),
        WsRelay::connect(&url).await.unwrap(),
    );
    let (id, frame) = test_frame();
    b.send(frame.clone()).await.unwrap();
    a.send(AskMsg::allocate(&id, 10)).await.unwrap();
    assert_eq!(a.next().await.unwrap(), frame);
}
