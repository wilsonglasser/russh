use std::convert::TryFrom;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures::FutureExt;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};

use bytes::Bytes;

use super::ChannelMsg;
use crate::ChannelId;

type BoxedThreadsafeFuture<T> = Pin<Box<dyn Sync + Send + std::future::Future<Output = T>>>;
type OwnedPermitFuture<S> = BoxedThreadsafeFuture<Result<OwnedPermit<S>, SendError<()>>>;

struct WatchNotification(Pin<Box<dyn Sync + Send + Future<Output = ()>>>);

/// A single future that becomes ready once the window size
/// changes to a positive value
impl WatchNotification {
    fn new(n: Arc<Notify>) -> Self {
        Self(Box::pin(async move { n.notified().await }))
    }
}

impl Future for WatchNotification {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.deref_mut().0.as_mut();
        ready!(inner.poll(cx));
        Poll::Ready(())
    }
}

/// Writes go in two steps, in this order: a place in the session's queue
/// (`permit`), then the window. The window is reserved and the message
/// handed over in one poll with no wait between, so a write that is
/// given up on while it waits (a timeout, a `select!`, the writer
/// dropped) has taken nothing from the window it will not use. The
/// place is kept across polls and across writes, so a write that was
/// waiting on the window resumes where it was.
pub struct ChannelTx<S> {
    sender: mpsc::Sender<S>,
    permit_fut: Option<OwnedPermitFuture<S>>,
    permit: Option<OwnedPermit<S>>,
    id: ChannelId,
    window_size_fut: Option<BoxedThreadsafeFuture<OwnedMutexGuard<u32>>>,
    window_size: Arc<Mutex<u32>>,
    notify: Arc<Notify>,
    window_size_notication: WatchNotification,
    max_packet_size: u32,
    ext: Option<u32>,
}

impl<S> ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send,
{
    pub fn new(
        sender: mpsc::Sender<S>,
        id: ChannelId,
        window_size: Arc<Mutex<u32>>,
        window_size_notification: Arc<Notify>,
        max_packet_size: u32,
        ext: Option<u32>,
    ) -> Self {
        Self {
            sender,
            permit_fut: None,
            permit: None,
            id,
            notify: Arc::clone(&window_size_notification),
            window_size_notication: WatchNotification::new(window_size_notification),
            window_size,
            window_size_fut: None,
            max_packet_size,
            ext,
        }
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>, buf_len: usize) -> Poll<NonZeroUsize> {
        let window_size = self.window_size.clone();
        let window_size_fut = self
            .window_size_fut
            .get_or_insert_with(|| Box::pin(window_size.lock_owned()));
        let mut window_size = ready!(window_size_fut.poll_unpin(cx));
        self.window_size_fut.take();

        let writable = (self.max_packet_size).min(*window_size).min(buf_len as u32) as usize;

        match NonZeroUsize::try_from(writable) {
            Ok(w) => {
                *window_size -= writable as u32;
                if *window_size > 0 {
                    self.notify.notify_one();
                }
                Poll::Ready(w)
            }
            Err(_) => {
                drop(window_size);
                ready!(self.window_size_notication.poll_unpin(cx));
                self.window_size_notication = WatchNotification::new(Arc::clone(&self.notify));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_mk_msg(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<(ChannelMsg, NonZeroUsize)> {
        let writable = ready!(self.poll_writable(cx, buf.len()));

        #[allow(clippy::indexing_slicing)] // Clamped to maximum `buf.len()` with `.poll_writable`
        let data = Bytes::copy_from_slice(&buf[..writable.into()]);

        let msg = match self.ext {
            None => ChannelMsg::Data { data },
            Some(ext) => ChannelMsg::ExtendedData { data, ext },
        };

        Poll::Ready((msg, writable))
    }

    /// A place in the session's queue, waited for before any window is
    /// reserved and held until a message takes it.
    fn poll_permit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.permit.is_some() {
            return Poll::Ready(Ok(()));
        }
        let sender = self.sender.clone();
        let permit_fut = self
            .permit_fut
            .get_or_insert_with(|| Box::pin(sender.reserve_owned()));
        let r = ready!(permit_fut.poll_unpin(cx));
        self.permit_fut = None;
        match r {
            Ok(permit) => {
                self.permit = Some(permit);
                Poll::Ready(Ok(()))
            }
            Err(SendError(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            ))),
        }
    }

    /// Hand `msg` to the session through the place taken by
    /// [`Self::poll_permit`]. Synchronous: nothing can interrupt it.
    fn send_with_permit(&mut self, msg: ChannelMsg) {
        if let Some(permit) = self.permit.take() {
            permit.send((self.id, msg).into());
        }
    }
}

impl<S> AsyncWrite for ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "cannot send empty buffer",
            )));
        }
        ready!(self.poll_permit(cx))?;
        let (msg, writable) = ready!(self.poll_mk_msg(cx, buf));
        self.send_with_permit(msg);
        Poll::Ready(Ok(writable.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        ready!(self.poll_permit(cx))?;
        self.send_with_permit(ChannelMsg::Eof);
        Poll::Ready(Ok(()))
    }
}

impl<S> Drop for ChannelTx<S> {
    fn drop(&mut self) {
        // Allow other writers to make progress
        self.notify.notify_one();
    }
}
