//! A sender with one channel out of window still serves the others. The
//! session takes application output for every channel as long as no
//! channel holds data it could not send, and with the writers' window
//! kept exact that only happens during a key exchange.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg, client};
use tokio::time::timeout;

const WINDOW: u32 = 64 * 1024;
/// Far over the window: the flood runs out of it and waits.
const FLOOD_CHUNKS: usize = 256;

/// The server floods channel A through `Channel::data`, the client never
/// reads A and (with per-channel flow control) never re-opens its window.
/// Channel B, opened and used while A is stuck, is answered.
#[tokio::test]
async fn a_channel_out_of_window_does_not_hold_the_others() -> Result<(), anyhow::Error> {
    let addr = common::addr();
    tokio::spawn(Server::run(addr));
    common::wait_for_server(addr).await;

    use russh::keys::PrivateKeyWithHashAlg;
    let config = Arc::new(client::Config {
        window_size: WINDOW,
        channel_buffer_size: 2,
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

    let _a = session.channel_open_session().await?;
    // Let the flood reach the end of A's window.
    tokio::time::sleep(Duration::from_millis(500)).await;

    for round in 0..8u8 {
        let mut b = timeout(Duration::from_secs(5), session.channel_open_session())
            .await
            .expect("B opens while A is out of window")?;
        b.data(&[round; 4][..]).await?;
        let echoed = timeout(Duration::from_secs(5), async {
            loop {
                match b.wait().await {
                    Some(ChannelMsg::Data { data }) => return data.to_vec(),
                    Some(_) => continue,
                    None => return Vec::new(),
                }
            }
        })
        .await
        .expect("B is answered while A is out of window");
        assert_eq!(echoed, [round; 4]);
    }
    Ok(())
}

#[derive(Clone)]
struct Server {
    first: bool,
}

impl Server {
    async fn run(addr: SocketAddr) {
        let config = common::server_config(WINDOW, 100);
        let mut sh = Server { first: true };
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
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        if std::mem::take(&mut self.first) {
            tokio::spawn(async move {
                let chunk = vec![7u8; 4096];
                for _ in 0..FLOOD_CHUNKS {
                    if channel.data(&chunk[..]).await.is_err() {
                        break;
                    }
                }
            });
        } else {
            tokio::spawn(async move {
                let mut channel = channel;
                while let Some(msg) = channel.wait().await {
                    if let ChannelMsg::Data { data } = msg
                        && channel.data(&data[..]).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
        Ok(())
    }
}
