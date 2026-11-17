use std::{future::Future, io, time::Duration};

const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// JNI callers must not wait forever for an uncancellable netd operation.
pub(super) struct ControlRuntime(Option<tokio::runtime::Runtime>);

impl ControlRuntime {
    pub(super) fn new() -> io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| Self(Some(runtime)))
    }

    pub(super) fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.0
            .as_ref()
            .expect("live control runtime")
            .block_on(future)
    }
}

impl Drop for ControlRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            // This does not cancel backend work. Its ownership fences and
            // preparation permits remain alive until that work actually ends.
            runtime.shutdown_timeout(SHUTDOWN_GRACE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, mpsc},
        thread,
    };

    #[test]
    fn teardown_is_bounded_on_success_error_and_unwind_with_backend_work_in_flight() {
        for outcome in 0..3 {
            let capacity = Arc::new(tokio::sync::Semaphore::new(1));
            let backend_capacity = Arc::clone(&capacity);
            let (release, held) = mpsc::channel();
            let (retired, backend_retired) = mpsc::channel();
            let (finished, response) = mpsc::channel();
            let worker = thread::spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let runtime = ControlRuntime::new().unwrap();
                    runtime.block_on(async {
                        let permit = backend_capacity.try_acquire_owned().unwrap();
                        let (entered, ready) = tokio::sync::oneshot::channel();
                        tokio::task::spawn_blocking(move || {
                            let _ = entered.send(());
                            // Model backend work that has already started and cannot abort.
                            let _ = held.recv();
                            drop(permit);
                            let _ = retired.send(());
                        });
                        ready.await.unwrap();
                        match outcome {
                            0 => Ok(()),
                            1 => Err("cancelled or timed out"),
                            _ => panic!("pairing unwind model"),
                        }
                    })
                }));
                let _ = finished.send(result);
            });
            let observed = response.recv_timeout(SHUTDOWN_GRACE + Duration::from_secs(2));
            let retained = capacity.available_permits();
            // Release before assertions so even a broken destructor cannot strand a test worker.
            let _ = release.send(());
            worker.join().unwrap();
            backend_retired
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            let observed =
                observed.expect("JNI runtime teardown must not wait for blocked backend work");
            assert_eq!(
                retained, 0,
                "shutdown must not release live preparation capacity"
            );
            match outcome {
                0 => assert!(matches!(observed, Ok(Ok(())))),
                1 => assert!(matches!(observed, Ok(Err(_)))),
                _ => assert!(observed.is_err()),
            }
            assert_eq!(capacity.available_permits(), 1);
        }
    }
}
