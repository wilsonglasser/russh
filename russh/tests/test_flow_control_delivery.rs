//! What per-channel flow control must not cost: every byte a peer sent
//! reaches a consumer that is slower than the network, in order, whether
//! the consumer falls behind for a while or the connection ends while it
//! still has a backlog to read.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg, Disconnect, client};
use tokio::time::timeout;

/// Small enough that a few packets fill it, so most of a transfer sits in
/// the session's backlog while the consumer is away.
const CHANNEL_BUFFER_SIZE: usize = 2;
const WINDOW_SIZE: u32 = 256 * 1024;

/// A byte that depends on its position, so a dropped, repeated or
/// reordered chunk shows as a mismatch and not only as a wrong total.
fn pattern(offset: usize) -> u8 {
    (offset % 251) as u8
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(pattern).collect()
}

/// Read a channel to its end, checking the pattern as it goes. Returns
/// the bytes read and whether the EOF arrived.
async fn read_checked(channel: &mut Channel<client::Msg>, pause_every: usize) -> (usize, bool) {
    let mut total = 0;
    let mut eof = false;
    let mut since_pause = 0;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                for (i, byte) in data.iter().enumerate() {
                    assert_eq!(*byte, pattern(total + i), "byte {} is wrong", total + i);
                }
                total += data.len();
                since_pause += data.len();
                if pause_every != 0 && since_pause >= pause_every {
                    since_pause = 0;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            ChannelMsg::Eof => eof = true,
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    (total, eof)
}

async fn connect(addr: SocketAddr) -> Result<client::Handle<common::Client>, anyhow::Error> {
    use russh::keys::PrivateKeyWithHashAlg;
    let config = Arc::new(client::Config {
        window_size: WINDOW_SIZE,
        channel_buffer_size: CHANNEL_BUFFER_SIZE,
        ..Default::default()
    });
    let key = Arc::new(
        ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap(),
    );
    let mut session = client::connect(config, addr, common::Client).await?;
    let auth = session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await?;
    assert!(auth.success());
    Ok(session)
}

/// A consumer that keeps falling behind (the backlog fills and drains many
/// times over) reads exactly what was sent.
#[tokio::test]
async fn slow_consumer_reads_every_byte_in_order() -> Result<(), anyhow::Error> {
    const LEN: usize = 8 * 1024 * 1024;
    let addr = common::addr();
    tokio::spawn(Server::run(addr, LEN, false));
    common::wait_for_server(addr).await;

    let session = connect(addr).await?;
    let mut channel = session.channel_open_session().await?;
    let (total, eof) = timeout(Duration::from_secs(60), read_checked(&mut channel, 64 * 1024))
        .await
        .expect("the transfer completes");
    assert_eq!(total, LEN);
    assert!(eof, "the EOF follows the data");
    Ok(())
}

/// The peer sends its data, its EOF and its close, and then ends the
/// connection, all before the consumer has read anything. The consumer
/// still reads the whole of it afterwards.
#[tokio::test]
async fn backlog_survives_the_end_of_the_connection() -> Result<(), anyhow::Error> {
    // Under the window, so the peer can send all of it without waiting on
    // the consumer, and far over what the channel buffer holds.
    const LEN: usize = 200 * 1024;
    let addr = common::addr();
    tokio::spawn(Server::run(addr, LEN, true));
    common::wait_for_server(addr).await;

    let session = connect(addr).await?;
    let mut channel = session.channel_open_session().await?;
    // The whole exchange, disconnect included, happens while nobody reads.
    timeout(Duration::from_secs(10), async {
        while !session.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the server ends the connection");

    let (total, eof) = timeout(Duration::from_secs(10), read_checked(&mut channel, 0))
        .await
        .expect("the channel ends");
    assert_eq!(total, LEN, "the tail was delivered");
    assert!(eof, "the EOF was delivered");
    Ok(())
}

#[derive(Clone)]
struct Server {
    len: usize,
    disconnect_after: bool,
}

impl Server {
    async fn run(addr: SocketAddr, len: usize, disconnect_after: bool) {
        let config = common::server_config(WINDOW_SIZE, 100);
        let mut sh = Server { len, disconnect_after };
        sh.run_on_address(config, addr).await.unwrap();
    }
}

impl russh::server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let handle = session.handle();
        let (len, disconnect_after) = (self.len, self.disconnect_after);
        tokio::spawn(async move {
            let data = payload(len);
            channel.data(&data[..]).await.unwrap();
            channel.eof().await.unwrap();
            channel.close().await.unwrap();
            if disconnect_after {
                let _ = handle
                    .disconnect(Disconnect::ByApplication, String::new(), String::new())
                    .await;
            }
        });
        Ok(())
    }
}
