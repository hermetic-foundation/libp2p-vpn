use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Waker},
};

#[derive(Debug, Default)]
struct WritableSocket {
    writable: AtomicBool,
    attempts: AtomicUsize,
    transmissions: AtomicUsize,
    writable_polls: AtomicUsize,
    waiter: Mutex<Option<Waker>>,
}

impl WritableSocket {
    fn make_writable(&self) {
        self.writable.store(true, Ordering::SeqCst);
        self.waiter.lock().unwrap().take().unwrap().wake();
    }
}

impl AsyncUdpSocket for WritableSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(WritablePoller(self))
    }

    fn try_send(&self, _: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if !self.writable.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.transmissions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        _: &mut [IoSliceMut<'_>],
        _: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        panic!("send regression must not receive")
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:51820".parse().unwrap())
    }
}

#[derive(Debug)]
struct WritablePoller(Arc<WritableSocket>);

impl quinn::UdpPoller for WritablePoller {
    fn poll_writable(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.writable_polls.fetch_add(1, Ordering::SeqCst);
        if self.0.writable.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            *self.0.waiter.lock().unwrap() = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

#[test]
fn writable_resume_after_deadline_cannot_attempt_or_transmit_another_datagram() {
    let fake = Arc::new(WritableSocket::default());
    let socket: Arc<dyn AsyncUdpSocket> = fake.clone();
    let destination = "127.0.0.1:51821".parse().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_millis(100);
    let mut sending = std::pin::pin!(send_before(
        &socket,
        b"probe",
        destination,
        None,
        None,
        Some(deadline),
    ));
    let mut context = Context::from_waker(futures::task::noop_waker_ref());

    assert!(sending.as_mut().poll(&mut context).is_pending());
    assert_eq!(fake.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(fake.writable_polls.load(Ordering::SeqCst), 1);
    assert_eq!(fake.transmissions.load(Ordering::SeqCst), 0);

    // The production guard uses the real clock, not Tokio's virtual time.
    while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(remaining);
    }
    fake.make_writable();
    let Poll::Ready(Err(error)) = sending.as_mut().poll(&mut context) else {
        panic!("expired writable send must fail immediately");
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(fake.writable_polls.load(Ordering::SeqCst), 2);
    assert_eq!(fake.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(fake.transmissions.load(Ordering::SeqCst), 0);
}

#[test]
fn writable_resume_without_deadline_transmits_the_pending_datagram() {
    let fake = Arc::new(WritableSocket::default());
    let socket: Arc<dyn AsyncUdpSocket> = fake.clone();
    let destination = "127.0.0.1:51821".parse().unwrap();
    let mut sending = std::pin::pin!(send_before(
        &socket,
        b"probe",
        destination,
        None,
        None,
        None,
    ));
    let mut context = Context::from_waker(futures::task::noop_waker_ref());

    assert!(sending.as_mut().poll(&mut context).is_pending());
    assert_eq!(fake.attempts.load(Ordering::SeqCst), 1);
    fake.make_writable();
    let Poll::Ready(Ok(len)) = sending.as_mut().poll(&mut context) else {
        panic!("unexpired writable send must complete");
    };
    assert_eq!(len, b"probe".len());
    assert_eq!(fake.writable_polls.load(Ordering::SeqCst), 2);
    assert_eq!(fake.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(fake.transmissions.load(Ordering::SeqCst), 1);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn expired_deadline_helper_never_polls_the_operation() {
    let polled = AtomicBool::new(false);
    let operation = async {
        polled.store(true, Ordering::SeqCst);
        Ok(())
    };
    let mut guarded = std::pin::pin!(super::super::udp_path::before_deadline(
        Some(std::time::Instant::now()),
        operation,
    ));
    let mut context = Context::from_waker(futures::task::noop_waker_ref());

    let Poll::Ready(Err(error)) = guarded.as_mut().poll(&mut context) else {
        panic!("expired operation must fail without requiring a runtime");
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(!polled.load(Ordering::SeqCst));
}

fn coalesced(bytes: &[u8], stride: usize) -> Receive {
    let mut receive = Receive {
        bytes: bytes.to_vec(),
        pending: None,
        offset: 0,
    };
    let mut meta = quinn::udp::RecvMeta::default();
    meta.len = bytes.len();
    meta.stride = stride;
    receive.pending = Some(meta);
    receive
}

#[test]
fn coalesced_ciphertexts_keep_independent_datagram_boundaries() {
    let mut receive = coalesced(b"abcDEFg", 3);
    let mut output = [0; 16];
    for expected in [b"abc".as_slice(), b"DEF", b"g"] {
        let (len, _) = receive.take(&mut output);
        assert_eq!(&output[..len], expected);
    }
    assert!(receive.pending.is_none());
}

#[test]
fn receive_batch_capacity_covers_large_valid_aggregates_without_oversized_datagrams() {
    assert_eq!(
        batch_capacity(1).unwrap(),
        PACKET_PLANE_MAX_UDP_DATAGRAM_LEN
    );
    assert_eq!(
        batch_capacity(64).unwrap(),
        64 * PACKET_PLANE_MAX_UDP_DATAGRAM_LEN
    );
    assert!(batch_capacity(0).is_err());
    assert!(batch_capacity(65).is_err());
    assert!(batch_capacity(usize::MAX).is_err());
    let stride = 1_400;
    let mut batch = Receive {
        bytes: vec![0; batch_capacity(64).unwrap()],
        pending: None,
        offset: 0,
    };
    for packet in 0..64 {
        batch.bytes[packet * stride..(packet + 1) * stride].fill(packet as u8);
    }
    let mut meta = quinn::udp::RecvMeta::default();
    meta.len = 64 * stride;
    meta.stride = stride;
    batch.pending = Some(meta);
    assert!(meta.len > PACKET_PLANE_MAX_UDP_DATAGRAM_LEN);
    for packet in 0..64 {
        let mut output = [0; 1_400];
        assert_eq!(batch.take(&mut output).0, stride);
        assert!(output.iter().all(|byte| *byte == packet));
    }
    assert!(batch.pending.is_none());
}

#[test]
fn truncation_discards_only_the_current_datagram_and_empty_datagrams_finish() {
    let mut receive = coalesced(b"abcDEF", 3);
    let mut output = [0; 2];
    assert_eq!(receive.take(&mut output).0, 2);
    assert_eq!(&output, b"ab");
    assert_eq!(receive.take(&mut output).0, 2);
    assert_eq!(&output, b"DE");
    assert!(receive.pending.is_none());
    for (bytes, stride) in [(b"".as_slice(), 0), (b"abc", 0)] {
        let mut receive = coalesced(bytes, stride);
        assert_eq!(receive.take(&mut [0; 16]).0, bytes.len());
        assert!(receive.pending.is_none());
    }
}

#[tokio::test]
async fn wildcard_receives_report_actual_destination_for_both_families() {
    for (wildcard, loopback) in [("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")] {
        let socket = Socket::bind(wildcard.parse().unwrap()).await.unwrap();
        let remote = tokio::net::UdpSocket::bind(loopback).await.unwrap();
        let destination = SocketAddr::new(
            remote.local_addr().unwrap().ip(),
            socket.local_addr().unwrap().port(),
        );
        remote.send_to(b"datagram", destination).await.unwrap();
        let mut bytes = [0; 32];
        let received = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.local, destination);
        assert_eq!(received.remote, remote.local_addr().unwrap());
        assert_eq!(&bytes[..received.len], b"datagram");
        socket.send_to(b"reply", received.remote).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), remote.recv(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            5
        );
    }
}

#[tokio::test]
async fn cancelled_receive_keeps_listener_available_for_later_packets() {
    let socket = Socket::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), socket.recv_from(&mut [0; 16]))
            .await
            .is_err()
    );
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(b"later", socket.local_addr().unwrap())
        .await
        .unwrap();
    let mut bytes = [0; 16];
    let received = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..received.len], b"later");
}
