# Local Patch

- Add `Transport::with_resolver` to inject a Network-scoped resolver.
- Preserve upstream DNS, DNS4, DNS6 and recursive DNSaddr parsing and limits.
- No changes to the existing Tokio constructors or Linux resolver behavior.
