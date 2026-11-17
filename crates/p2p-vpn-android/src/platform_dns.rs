//! Public API 29 resolver calls with defensive runtime capability checks.

use std::{
    ffi::{CStr, c_int, c_void},
    io,
    os::fd::{AsRawFd, RawFd},
};

const MIN_MESSAGE_LENGTH: usize = 12;
const MAX_MESSAGE_LENGTH: usize = 65_535;
const ANDROID_RESOLV_NO_RETRY: u32 = 1;

type SendQuery = unsafe extern "C" fn(u64, *const u8, usize, u32) -> c_int;
type QueryResult = unsafe extern "C" fn(c_int, *mut c_int, *mut u8, usize) -> c_int;
type CancelQuery = unsafe extern "C" fn(c_int);

#[derive(Clone, Copy, Debug)]
struct Functions {
    send: SendQuery,
    result: QueryResult,
    cancel: CancelQuery,
    set_nonblocking: fn(RawFd, bool) -> io::Result<()>,
}

impl Functions {
    /// Each non-null symbol must have the named public NDK function's ABI and
    /// remain loaded for the lifetime of every query using this table.
    unsafe fn load_with(
        mut symbol: impl FnMut(&CStr) -> *mut c_void,
        set_nonblocking: fn(RawFd, bool) -> io::Result<()>,
    ) -> Option<Self> {
        let send = symbol(c"android_res_nsend");
        let result = symbol(c"android_res_nresult");
        let cancel = symbol(c"android_res_cancel");
        if send.is_null() || result.is_null() || cancel.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees these exact public NDK signatures.
        Some(unsafe {
            Self {
                send: std::mem::transmute::<*mut c_void, SendQuery>(send),
                result: std::mem::transmute::<*mut c_void, QueryResult>(result),
                cancel: std::mem::transmute::<*mut c_void, CancelQuery>(cancel),
                set_nonblocking,
            }
        })
    }

    fn start(self, network: u64, message: &[u8]) -> io::Result<Query> {
        if network == 0 || !(MIN_MESSAGE_LENGTH..=MAX_MESSAGE_LENGTH).contains(&message.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Platform DNS requires an explicit Network and a 12..=65535 byte message",
            ));
        }
        // SAFETY: message is readable for its supplied length during this call.
        // Pass the Network unchanged, with no Private DNS bypass or netid flags.
        let fd = unsafe {
            (self.send)(
                network,
                message.as_ptr(),
                message.len(),
                ANDROID_RESOLV_NO_RETRY,
            )
        };
        if fd < 0 {
            return Err(negative_errno(fd));
        }
        let query = Query {
            fd: Some(fd),
            functions: self,
        };
        // AsyncFd requires nonblocking mode. Establish ownership first so an
        // fcntl error cancels the submitted query exactly once.
        (self.set_nonblocking)(fd, true)?;
        Ok(query)
    }
}

#[cfg(target_os = "android")]
fn functions() -> Option<Functions> {
    static FUNCTIONS: std::sync::OnceLock<Option<Functions>> = std::sync::OnceLock::new();
    *FUNCTIONS.get_or_init(|| {
        // SAFETY: libandroid is already linked by AndroidSocketBinder and remains
        // loaded. Only these named public symbols are converted to function pointers.
        unsafe {
            Functions::load_with(
                |name| libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()),
                set_nonblocking,
            )
        }
    })
}

#[cfg(target_os = "android")]
fn set_nonblocking(fd: RawFd, enabled: bool) -> io::Result<()> {
    // SAFETY: the caller retains sole ownership of this live descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if enabled {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: F_SETFL takes the integer flags argument and does not consume fd.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "android")]
pub(crate) fn supported() -> bool {
    functions().is_some()
}

#[cfg(target_os = "android")]
pub(crate) fn start(
    network: u64,
    message: &[u8],
) -> io::Result<Box<dyn p2p_vpn::runtime::physical_network::android::PlatformDnsQuery>> {
    let functions = functions().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "Public platform DNS API unavailable",
        )
    })?;
    Ok(Box::new(functions.start(network, message)?))
}

#[derive(Debug)]
struct Query {
    fd: Option<RawFd>,
    functions: Functions,
}

impl Query {
    fn finish_result(mut self) -> io::Result<Vec<u8>> {
        let mut answer = vec![0; MAX_MESSAGE_LENGTH];
        let mut rcode = 0;
        // Only called on the bounded blocking worker after removal from AsyncFd.
        // Readiness can precede a complete result frame; nresult must not EAGAIN
        // midway through that frame. A mode error leaves Drop owning cancellation.
        (self.functions.set_nonblocking)(self.as_raw_fd(), false)?;
        // nresult closes on every return path. Relinquish ownership before FFI
        // so Drop never cancels or closes that descriptor a second time.
        let fd = self.fd.take().expect("pending platform DNS descriptor");
        // SAFETY: the fd is transferred exactly once, and both output buffers
        // are writable for the lengths required by the public NDK signature.
        let length =
            unsafe { (self.functions.result)(fd, &mut rcode, answer.as_mut_ptr(), answer.len()) };
        if length < 0 {
            return Err(negative_errno(length));
        }
        let length = length as usize;
        if !(MIN_MESSAGE_LENGTH..=MAX_MESSAGE_LENGTH).contains(&length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Platform DNS returned an invalid response length",
            ));
        }
        if answer[2] & 0x02 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Platform DNS returned a truncated response",
            ));
        }
        // DNS rcodes (including NXDOMAIN) belong to the wire response, not errno.
        answer.truncate(length);
        Ok(answer)
    }
}

impl AsRawFd for Query {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.expect("pending platform DNS descriptor")
    }
}

#[cfg(target_os = "android")]
impl p2p_vpn::runtime::physical_network::android::PlatformDnsQuery for Query {
    fn finish(self: Box<Self>) -> io::Result<Vec<u8>> {
        (*self).finish_result()
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            // SAFETY: this is the sole owner of an unconsumed result fd.
            // android_res_cancel -> resNetworkCancel -> close(fd), see AOSP:
            // platform/frameworks/base/native/android/net.c and
            // platform/system/netd/client/NetdClient.cpp. Do not also close it.
            unsafe { (self.functions.cancel)(fd) };
        }
    }
}

fn negative_errno(result: c_int) -> io::Error {
    match result.checked_neg() {
        Some(errno) if errno > 0 => io::Error::from_raw_os_error(errno),
        _ => io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid platform DNS error code",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug, PartialEq)]
    enum Event {
        Send(u64, Vec<u8>, u32),
        Mode(RawFd, bool),
        Result(RawFd, usize),
        Cancel(RawFd),
    }

    struct State {
        send_return: c_int,
        result_return: c_int,
        response: Vec<u8>,
        fail_mode: Option<bool>,
        events: Vec<Event>,
    }

    impl Default for State {
        fn default() -> Self {
            Self {
                send_return: 42,
                result_return: 12,
                response: vec![0; 12],
                fail_mode: None,
                events: Vec::new(),
            }
        }
    }

    thread_local! {
        static STATE: RefCell<State> = RefCell::new(State::default());
    }

    unsafe extern "C" fn send(
        network: u64,
        message: *const u8,
        length: usize,
        flags: u32,
    ) -> c_int {
        // SAFETY: Functions::start supplies a live input slice.
        let message = unsafe { std::slice::from_raw_parts(message, length) }.to_vec();
        STATE.with_borrow_mut(|state| {
            state.events.push(Event::Send(network, message, flags));
            state.send_return
        })
    }

    unsafe extern "C" fn result(
        fd: c_int,
        rcode: *mut c_int,
        answer: *mut u8,
        length: usize,
    ) -> c_int {
        STATE.with_borrow_mut(|state| {
            state.events.push(Event::Result(fd, length));
            // SAFETY: Query supplies writable output buffers. Deliberately allow
            // impossible return lengths without writing outside the buffer.
            unsafe {
                *rcode = c_int::from(state.response.get(3).copied().unwrap_or(0) & 0x0f);
                std::ptr::copy_nonoverlapping(
                    state.response.as_ptr(),
                    answer,
                    state.response.len().min(length),
                );
            }
            state.result_return
        })
    }

    unsafe extern "C" fn cancel(fd: c_int) {
        STATE.with_borrow_mut(|state| state.events.push(Event::Cancel(fd)));
    }

    fn set_mode(fd: RawFd, enabled: bool) -> io::Result<()> {
        STATE.with_borrow_mut(|state| {
            state.events.push(Event::Mode(fd, enabled));
            if state.fail_mode == Some(enabled) {
                Err(io::Error::from_raw_os_error(9))
            } else {
                Ok(())
            }
        })
    }

    fn table() -> Functions {
        STATE.with_borrow_mut(|state| *state = State::default());
        Functions {
            send,
            result,
            cancel,
            set_nonblocking: set_mode,
        }
    }

    #[test]
    fn all_three_public_symbols_are_required() {
        for present in 0..8 {
            let mut names = Vec::new();
            // SAFETY: all non-null pointers refer to matching static fake functions.
            let loaded = unsafe {
                Functions::load_with(
                    |name| {
                        names.push(name.to_owned());
                        let (bit, pointer) = match name.to_bytes() {
                            b"android_res_nsend" => (1, send as *const () as *mut c_void),
                            b"android_res_nresult" => (2, result as *const () as *mut c_void),
                            b"android_res_cancel" => (4, cancel as *const () as *mut c_void),
                            _ => panic!("unexpected platform DNS symbol"),
                        };
                        if present & bit != 0 {
                            pointer
                        } else {
                            std::ptr::null_mut()
                        }
                    },
                    set_mode,
                )
            };
            assert_eq!(loaded.is_some(), present == 7);
            assert_eq!(names.len(), 3);
        }
    }

    #[test]
    fn validates_network_and_message_before_ffi() {
        let functions = table();
        for (network, length) in [(0, 12), (1, 0), (1, 11), (1, 65_536)] {
            let error = functions.start(network, &vec![0; length]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        STATE.with_borrow(|state| assert!(state.events.is_empty()));
    }

    #[test]
    fn sends_exact_network_message_and_only_no_retry_then_cancels_once() {
        let functions = table();
        let network = 0x1234_cafe_d00d;
        let message = vec![0x5a; 12];
        let query = functions.start(network, &message).unwrap();
        assert_eq!(query.as_raw_fd(), 42);
        drop(query);
        STATE.with_borrow(|state| {
            assert_eq!(
                state.events,
                [
                    Event::Send(network, message, 1),
                    Event::Mode(42, true),
                    Event::Cancel(42)
                ]
            );
        });
    }

    #[test]
    fn accepts_maximum_wire_message_and_descriptor_zero() {
        let functions = table();
        STATE.with_borrow_mut(|state| state.send_return = 0);
        let query = functions.start(1, &vec![0; MAX_MESSAGE_LENGTH]).unwrap();
        assert_eq!(query.as_raw_fd(), 0);
        drop(query);
        STATE.with_borrow(|state| assert_eq!(state.events.last(), Some(&Event::Cancel(0))));
    }

    #[test]
    fn immediate_error_uses_negative_errno_and_owns_no_descriptor() {
        let functions = table();
        STATE.with_borrow_mut(|state| state.send_return = -13);
        assert_eq!(
            functions.start(1, &[0; 12]).unwrap_err().raw_os_error(),
            Some(13)
        );
        STATE.with_borrow(|state| assert_eq!(state.events.len(), 1));
    }

    #[test]
    fn finish_preserves_dns_error_response_without_cancelling() {
        let functions = table();
        STATE.with_borrow_mut(|state| state.response[3] = 3);
        let answer = functions
            .start(1, &[0; 12])
            .unwrap()
            .finish_result()
            .unwrap();
        assert_eq!(answer.len(), 12);
        assert_eq!(answer[3], 3);
        STATE.with_borrow(|state| {
            assert_eq!(state.events.len(), 4);
            assert_eq!(state.events[1], Event::Mode(42, true));
            assert_eq!(state.events[2], Event::Mode(42, false));
            assert_eq!(state.events[3], Event::Result(42, MAX_MESSAGE_LENGTH));
        });
    }

    #[test]
    fn finish_accepts_maximum_response() {
        let functions = table();
        STATE.with_borrow_mut(|state| {
            state.result_return = MAX_MESSAGE_LENGTH as c_int;
            state.response = vec![0; MAX_MESSAGE_LENGTH];
        });
        let answer = functions
            .start(1, &[0; 12])
            .unwrap()
            .finish_result()
            .unwrap();
        assert_eq!(answer.len(), MAX_MESSAGE_LENGTH);
    }

    #[test]
    fn finish_errors_never_cancel_an_already_consumed_descriptor() {
        for length in [-5, c_int::MIN, 0, 11, 65_536] {
            let functions = table();
            STATE.with_borrow_mut(|state| state.result_return = length);
            let error = functions
                .start(1, &[0; 12])
                .unwrap()
                .finish_result()
                .unwrap_err();
            if length == -5 {
                assert_eq!(error.raw_os_error(), Some(5));
            } else {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            STATE.with_borrow(|state| {
                assert_eq!(state.events.len(), 4);
                assert_eq!(state.events[3], Event::Result(42, MAX_MESSAGE_LENGTH));
            });
        }
    }

    #[test]
    fn rejects_truncated_dns_response_without_cancelling() {
        let functions = table();
        STATE.with_borrow_mut(|state| state.response[2] = 0x02);
        let error = functions
            .start(1, &[0; 12])
            .unwrap()
            .finish_result()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        STATE.with_borrow(|state| assert_eq!(state.events.len(), 4));
    }

    #[test]
    fn mode_errors_cancel_once_before_or_after_polling() {
        for enabled in [true, false] {
            let functions = table();
            STATE.with_borrow_mut(|state| state.fail_mode = Some(enabled));
            let error = match functions.start(1, &[0; 12]) {
                Ok(query) => query.finish_result().unwrap_err(),
                Err(error) => error,
            };
            assert_eq!(error.raw_os_error(), Some(9));
            STATE.with_borrow(|state| {
                let mut expected = vec![Event::Send(1, vec![0; 12], 1), Event::Mode(42, true)];
                if !enabled {
                    expected.push(Event::Mode(42, false));
                }
                expected.push(Event::Cancel(42));
                assert_eq!(state.events, expected);
            });
        }
    }

    #[test]
    fn query_is_send_sync() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<Query>();
    }
}
