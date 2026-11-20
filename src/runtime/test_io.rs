use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::io::{AsyncRead, Cursor};

pub(super) struct ReadRecorder<T> {
    input: Cursor<T>,
    pub(super) requested: Vec<usize>,
}

impl<T> ReadRecorder<T> {
    pub(super) fn new(bytes: T) -> Self {
        Self {
            input: Cursor::new(bytes),
            requested: Vec::new(),
        }
    }
}

impl<T: AsRef<[u8]> + Unpin> AsyncRead for ReadRecorder<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.requested.push(buffer.len());
        Pin::new(&mut this.input).poll_read(cx, buffer)
    }
}
