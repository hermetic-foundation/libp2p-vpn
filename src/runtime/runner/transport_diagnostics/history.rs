//! A bounded actor-local diagnostic history; no timers, I/O or routing state.

use std::{
    cell::RefCell,
    collections::VecDeque,
    future::Future,
    time::{Duration, Instant},
};

const MAX_ENTRIES: usize = 96;
const MAX_LINE_BYTES: usize = 1_024;
const MAX_AGE: Duration = Duration::from_secs(300);

tokio::task_local! {
    static EVENTS: RefCell<History>;
}

pub(in super::super) async fn scope<F: Future>(future: F) -> F::Output {
    EVENTS.scope(RefCell::new(History::default()), future).await
}

pub(in super::super) fn record(event: &str, fields: &[(&str, &str)], line: &str) {
    if event != "connection_closed"
        && event != "relay_client_limit"
        && event != "relay_listen_address_ready"
        && event != "relay_server_external_address_advertised"
        && event != "public_routing_connection_rejected"
        && event != "membership_probe_peer_quarantined"
        && !fields.iter().any(|(key, _)| *key == "close_requested")
    {
        return;
    }
    let _ = EVENTS.try_with(|history| history.borrow_mut().push(line, Instant::now()));
}

pub(super) fn snapshot() -> Vec<String> {
    EVENTS
        .try_with(|history| history.borrow().lines(Instant::now()))
        .unwrap_or_default()
}

#[derive(Default)]
struct History {
    next: u64,
    overwritten: u64,
    entries: VecDeque<Entry>,
}

struct Entry {
    sequence: u64,
    at: Instant,
    truncated: bool,
    line: String,
}

impl History {
    fn push(&mut self, line: &str, now: Instant) {
        while self
            .entries
            .front()
            .is_some_and(|entry| now.saturating_duration_since(entry.at) > MAX_AGE)
        {
            self.entries.pop_front();
        }
        if self.entries.len() == MAX_ENTRIES {
            self.entries.pop_front();
            self.overwritten = self.overwritten.saturating_add(1);
        }
        let mut end = line.len().min(MAX_LINE_BYTES);
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        self.next = self.next.saturating_add(1);
        self.entries.push_back(Entry {
            sequence: self.next,
            at: now,
            truncated: end < line.len(),
            line: line[..end].to_owned(),
        });
    }

    fn lines(&self, now: Instant) -> Vec<String> {
        let mut lines = vec![format!(
            "transport_event_history_overwritten {}",
            self.overwritten
        )];
        for entry in &self.entries {
            let age = now.saturating_duration_since(entry.at);
            if age <= MAX_AGE {
                lines.push(format!(
                    "transport event: seq={:020} age_millis={} truncated={} {}",
                    entry.sequence,
                    age.as_millis(),
                    entry.truncated,
                    entry.line,
                ));
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_entry_count_bytes_and_reports_overwrite_and_truncation() {
        let mut history = History::default();
        let now = Instant::now();
        for _ in 0..MAX_ENTRIES + 1 {
            history.push(&format!("a{}", "\u{1f600}".repeat(MAX_LINE_BYTES)), now);
        }
        assert_eq!(history.entries.len(), MAX_ENTRIES);
        assert_eq!(history.overwritten, 1);
        assert!(
            history
                .entries
                .iter()
                .all(|entry| entry.truncated && entry.line.len() <= MAX_LINE_BYTES)
        );
        let lines = history.lines(now);
        assert_eq!(lines.len(), MAX_ENTRIES + 1);
        assert!(lines[1].contains("seq=00000000000000000002 age_millis=0 truncated=true"));
        assert!(lines.iter().map(String::len).sum::<usize>() < 128 * 1_024);
    }

    #[test]
    fn ages_out_without_scheduling_work_or_mutating_runtime_state() {
        let mut history = History::default();
        let now = Instant::now();
        history.push("first", now);
        assert_eq!(history.lines(now + MAX_AGE).len(), 2);
        assert_eq!(
            history.lines(now + MAX_AGE + Duration::from_nanos(1)).len(),
            1
        );
        history.push("second", now + MAX_AGE + Duration::from_secs(1));
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].line, "second");
        assert_eq!(history.overwritten, 0);
    }

    #[tokio::test]
    async fn runtime_scopes_are_isolated_and_do_not_capture_unrelated_events() {
        assert!(snapshot().is_empty());
        scope(async {
            record(
                "pairing_code_created",
                &[],
                "must-not-retain-pairing-secret",
            );
            record("connection_closed", &[], "outer-close");
            scope(async {
                assert_eq!(snapshot(), ["transport_event_history_overwritten 0"]);
                record("retire", &[("close_requested", "true")], "inner-retirement");
                assert!(
                    snapshot()
                        .iter()
                        .any(|line| line.contains("inner-retirement"))
                );
                assert!(!snapshot().iter().any(|line| line.contains("outer-close")));
            })
            .await;
            let lines = snapshot();
            assert!(lines.iter().any(|line| line.contains("outer-close")));
            assert!(
                !lines.iter().any(
                    |line| line.contains("pairing-secret") || line.contains("inner-retirement")
                )
            );
        })
        .await;
        assert!(snapshot().is_empty());
    }
}
