//! One live, bounded transport view requested explicitly by the Android caller.

use std::io::{self, Write};
use std::sync::{Mutex, MutexGuard, TryLockError};

use p2p_vpn::runtime::control_socket::RuntimeControlHandle;
use serde::Serialize;

const MAX_LINES: usize = 4_096;
const MAX_LINE_BYTES: usize = 8 * 1_024;
const MAX_BYTES: usize = 256 * 1_024;

pub(super) fn try_read<T>(lock: &Mutex<T>) -> Result<MutexGuard<'_, T>, String> {
    match lock.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(TryLockError::WouldBlock) => Err("transport snapshot runtime is busy".to_owned()),
    }
}

#[derive(Debug, Serialize)]
pub(super) struct TransportSnapshot {
    schema_version: u8,
    network_id: String,
    lines: Vec<String>,
}

pub(super) fn validate_network_id(network_id: &str) -> io::Result<()> {
    if !super::is_canonical_android_network_id(network_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport snapshot requires a canonical Android network ID",
        ));
    }
    Ok(())
}

pub(super) async fn capture(
    control: &RuntimeControlHandle,
    network_id: &str,
) -> io::Result<TransportSnapshot> {
    validate_network_id(network_id)?;
    let lines = control.state().await?;
    TransportSnapshot::from_lines(network_id, lines)
}

impl TransportSnapshot {
    fn from_lines(network_id: &str, lines: Vec<String>) -> io::Result<Self> {
        validate_network_id(network_id)?;
        if lines.len() > MAX_LINES {
            return Err(oversized("transport snapshot exceeds 4096 lines"));
        }
        let mut raw_bytes = network_id.len();
        for line in &lines {
            if line.len() > MAX_LINE_BYTES {
                return Err(oversized("transport snapshot line exceeds 8 KiB"));
            }
            raw_bytes = raw_bytes
                .checked_add(line.len())
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or_else(|| oversized("transport snapshot raw data exceeds 256 KiB"))?;
        }
        let snapshot = Self {
            schema_version: 1,
            network_id: network_id.to_owned(),
            lines,
        };
        // Count the actual JNI envelope and escaping without allocating its JSON.
        let response = super::BridgeResponse {
            ok: true,
            value: Some(&snapshot),
            error: None,
        };
        serde_json::to_writer(JsonBudget(MAX_BYTES), &response)
            .map_err(|_| oversized("transport snapshot JSON response exceeds 256 KiB"))?;
        Ok(snapshot)
    }
}

fn oversized(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct JsonBudget(usize);

impl Write for JsonBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| oversized("transport snapshot JSON budget exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_vpn::runtime::control_socket::{
        RuntimeControlReceiver, RuntimeControlRequest, runtime_control_channel,
    };
    use std::{future::Future, time::Duration};

    const NETWORK_ID: &str = "00000000-0000-4000-8000-000000000001";
    const TEST_TIMEOUT: Duration = Duration::from_millis(25);

    #[test]
    fn runtime_selection_locks_fail_fast_on_contention() {
        let state = Mutex::new(42);
        let held = state.lock().unwrap();
        assert!(try_read(&state).unwrap_err().contains("busy"));
        drop(held);
        assert_eq!(*try_read(&state).unwrap(), 42);
    }

    fn run(future: impl Future<Output = ()>) {
        super::super::control_runtime::ControlRuntime::new()
            .unwrap()
            .block_on(future);
    }

    async fn assert_no_more_requests(receiver: &mut RuntimeControlReceiver) {
        assert!(
            tokio::time::timeout(TEST_TIMEOUT, receiver.recv())
                .await
                .is_err()
        );
    }

    async fn capture_lines(lines: Vec<String>) -> io::Result<TransportSnapshot> {
        let (control, mut receiver) = runtime_control_channel();
        let responder = tokio::spawn(async move {
            let Some(RuntimeControlRequest::State { respond_to }) = receiver.recv().await else {
                panic!("transport snapshot must request exactly the State view");
            };
            respond_to.send(lines).unwrap();
            assert_no_more_requests(&mut receiver).await;
        });
        let result = capture(&control, NETWORK_ID).await;
        responder.await.unwrap();
        result
    }

    fn encoded_response(snapshot: &TransportSnapshot) -> Vec<u8> {
        serde_json::to_vec(&super::super::BridgeResponse {
            ok: true,
            value: Some(snapshot),
            error: None,
        })
        .unwrap()
    }

    #[test]
    fn one_live_state_query_preserves_peer_capabilities_paths_and_owners() {
        run(async {
            let lines = vec![
                "peer state: peer-a validated true selected_path circuit_relay".into(),
                "peer capability state: peer-a owned_udp false owned_quic false".into(),
                "peer path state: peer-a circuit_relay healthy true connection_id 42".into(),
                "physical_owner connection_id=42 outer=7 generation=3".into(),
                "quoted \"field\" with \\ separator\nnext line".into(),
            ];
            let snapshot = capture_lines(lines.clone()).await.unwrap();
            assert_eq!(snapshot.schema_version, 1);
            assert_eq!(snapshot.network_id, NETWORK_ID);
            assert_eq!(snapshot.lines, lines);
            let encoded = encoded_response(&snapshot);
            let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["value"]["schema_version"], 1);
            assert_eq!(value["value"]["network_id"], NETWORK_ID);
            assert_eq!(value["value"]["lines"], serde_json::json!(lines));
        });
    }

    #[test]
    fn missing_control_receiver_preserves_the_runtime_error() {
        run(async {
            let (control, receiver) = runtime_control_channel();
            drop(receiver);
            let error = capture(&control, NETWORK_ID).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        });
    }

    #[test]
    fn dropped_response_returns_an_error_without_retrying() {
        run(async {
            let (control, mut receiver) = runtime_control_channel();
            let responder = tokio::spawn(async move {
                let Some(RuntimeControlRequest::State { respond_to }) = receiver.recv().await
                else {
                    panic!("expected State request");
                };
                drop(respond_to);
                assert_no_more_requests(&mut receiver).await;
            });
            assert_eq!(
                capture(&control, NETWORK_ID).await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe,
            );
            responder.await.unwrap();
        });
    }

    #[test]
    fn timeout_cancels_the_response_wait_and_leaves_no_retry_task() {
        run(async {
            let (control, mut receiver) = runtime_control_channel();
            let (entered, waiting) = tokio::sync::oneshot::channel();
            let responder = tokio::spawn(async move {
                let Some(RuntimeControlRequest::State { mut respond_to }) = receiver.recv().await
                else {
                    panic!("expected State request");
                };
                entered.send(()).unwrap();
                respond_to.closed().await;
                assert!(respond_to.send(Vec::new()).is_err());
                assert_no_more_requests(&mut receiver).await;
            });
            let request = tokio::spawn(async move {
                tokio::time::timeout(TEST_TIMEOUT, capture(&control, NETWORK_ID)).await
            });
            waiting.await.unwrap();
            assert!(request.await.unwrap().is_err());
            responder.await.unwrap();
        });
    }

    #[test]
    fn invalid_network_ids_never_submit_a_state_request() {
        run(async {
            for id in [
                "".to_owned(),
                "a".repeat(4_096),
                "00000000-0000-4000-8000-00000000000A".to_owned(),
                "00000000_0000-4000-8000-000000000001".to_owned(),
                format!("{NETWORK_ID}\n"),
            ] {
                let (control, mut receiver) = runtime_control_channel();
                assert_eq!(
                    capture(&control, &id).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                );
                assert_no_more_requests(&mut receiver).await;
            }
        });
    }

    #[test]
    fn line_count_limit_accepts_the_boundary_and_rejects_excess() {
        run(async {
            assert_eq!(
                capture_lines(vec![String::new(); MAX_LINES])
                    .await
                    .unwrap()
                    .lines
                    .len(),
                MAX_LINES
            );
            assert_eq!(
                capture_lines(vec![String::new(); MAX_LINES + 1])
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        });
    }

    #[test]
    fn line_length_is_bounded_in_utf8_bytes_without_truncation() {
        run(async {
            let line = "\u{1f600}".repeat(MAX_LINE_BYTES / 4);
            assert_eq!(
                capture_lines(vec![line.clone()]).await.unwrap().lines,
                [line]
            );
            assert_eq!(
                capture_lines(vec!["x".repeat(MAX_LINE_BYTES + 1)])
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                capture_lines(vec!["\u{1f600}".repeat(MAX_LINE_BYTES / 4 + 1)])
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        });
    }

    #[test]
    fn raw_total_limit_rejects_many_individually_valid_lines() {
        run(async {
            let error = capture_lines(vec![
                "x".repeat(MAX_LINE_BYTES);
                MAX_BYTES / MAX_LINE_BYTES + 1
            ])
            .await
            .unwrap_err();
            assert!(error.to_string().contains("raw data"));
        });
    }

    #[test]
    fn serialized_budget_includes_array_and_bridge_envelope_overhead() {
        run(async {
            let mut lines = vec!["x".repeat(MAX_LINE_BYTES); MAX_BYTES / MAX_LINE_BYTES - 1];
            lines.push(String::new());
            let base = TransportSnapshot {
                schema_version: 1,
                network_id: NETWORK_ID.to_owned(),
                lines: lines.clone(),
            };
            let remaining = MAX_BYTES - encoded_response(&base).len();
            assert!(remaining < MAX_LINE_BYTES);
            *lines.last_mut().unwrap() = "x".repeat(remaining);
            let snapshot = capture_lines(lines.clone()).await.unwrap();
            assert_eq!(encoded_response(&snapshot).len(), MAX_BYTES);
            lines.last_mut().unwrap().push('x');
            let error = capture_lines(lines).await.unwrap_err();
            assert!(error.to_string().contains("JSON response"));
        });
    }

    #[test]
    fn json_escape_expansion_cannot_bypass_the_response_budget() {
        run(async {
            let lines = vec!["\0".repeat(MAX_LINE_BYTES); 6];
            assert!(lines.iter().map(String::len).sum::<usize>() < MAX_BYTES);
            let error = capture_lines(lines).await.unwrap_err();
            assert!(error.to_string().contains("JSON response"));
        });
    }
}
