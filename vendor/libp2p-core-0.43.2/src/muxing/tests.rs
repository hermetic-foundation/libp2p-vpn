use std::{
    io,
    marker::PhantomPinned,
    sync::{Arc, Mutex},
};

use futures::future::Either;

use super::*;

struct RecordingMuxer {
    calls: Arc<Mutex<Vec<usize>>>,
    _pinned: PhantomPinned,
}

impl StreamMuxer for RecordingMuxer {
    type Substream = futures::io::Cursor<Vec<u8>>;
    type Error = io::Error;

    fn on_swarm_connection(self: Pin<&mut Self>, connection_id: usize) {
        self.calls.lock().unwrap().push(connection_id);
    }

    fn poll_inbound(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        Poll::Pending
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        Poll::Pending
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        Poll::Pending
    }
}

#[test]
fn swarm_connection_hook_survives_nested_boxing_of_pinned_muxer() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let muxer = RecordingMuxer {
        calls: calls.clone(),
        _pinned: PhantomPinned,
    };
    let mut muxer = StreamMuxerBox::new(StreamMuxerBox::new(muxer));

    assert!(calls.lock().unwrap().is_empty());
    Pin::new(&mut muxer).on_swarm_connection(usize::MAX);
    assert_eq!(*calls.lock().unwrap(), [usize::MAX]);
}

#[test]
fn swarm_connection_hook_reaches_both_either_variants() {
    for left in [true, false] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingMuxer {
            calls: calls.clone(),
            _pinned: PhantomPinned,
        };
        let muxer: Either<RecordingMuxer, RecordingMuxer> = if left {
            Either::Left(inner)
        } else {
            Either::Right(inner)
        };
        let mut muxer = StreamMuxerBox::new(muxer);

        Pin::new(&mut muxer).on_swarm_connection(37);
        assert_eq!(*calls.lock().unwrap(), [37]);
    }
}
