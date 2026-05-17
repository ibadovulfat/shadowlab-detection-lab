# Changelog

All notable changes to ShadowLab are tracked in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project version scheme follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.8] - 2026-05-12

### Security

- **CRITICAL** `PUT` method was missing from the signed-request and audit
  gate. Five admin-level routes (`/antivirus/yara/custom/{name}`,
  `/antivirus/lists/{kind}`, `/antivirus/policy`, `/antivirus/credentials`,
  `/yara/local/policy`) previously bypassed request signing, MFA
  enforcement, Origin allow-list, audit logging, and approval consumption.
  Both `api/security.py` and `api/middleware/security_headers.py` now
  include `PUT` in their mutating-method sets.
- **HIGH** MFA verify is rate limited and subject to lockout. The TOTP
  verify endpoint now uses an IP-scoped rate limit bucket plus a per-
  subject lockout that triggers after 5 consecutive failed codes inside
  a 15 minute window. Locked subjects receive HTTP 423 with a
  `retry_after_seconds` hint. Database schema is extended with three
  columns on `mfa_enrollments` (`failed_attempts`, `first_failure_at`,
  `locked_until`); the migration is automatic and idempotent.
- **HIGH** API key configuration refuses to bind the same token to more
  than one role. The previous validator only checked uniqueness inside a
  single role; an operator typo that assigned the same secret to both
  `admin` and `viewer` historically resulted in silent privilege confusion
  driven by `dict` insertion order. `_validate_settings` now fails closed.
- **HIGH** OIDC RSA verification enforces a 2048-bit minimum modulus and
  rejects exotic exponents. JWTs signed under a 1024-bit RSA key are no
  longer accepted under any policy profile.
- **HIGH** OIDC `iss` claim is anchored to the discovered issuer when only
  `SHADOWLAB_OIDC_DISCOVERY_URL` is configured. Previously, deployments
  that relied solely on discovery never validated the `iss` claim and
  could accept any JWT signed by the matching JWKS regardless of tenant.
- **HIGH** Outbound webhook DNS-rebinding TOCTOU is closed via a pinned
  resolve-then-connect path. `resolve_safe_outbound_address` returns one
  validated IP, and the dispatcher swaps `socket.getaddrinfo` for the
  duration of the request so the HTTP stack cannot re-resolve to an
  internal address after validation.
- **HIGH** MFA enrollment now requires `subject` and `account_label` to
  match an explicit pattern. CR/LF or `:` characters in `account_label`
  can no longer split an `otpauth://` URI inside the resulting QR code.
- **HIGH** Signed-request canonical query strings are RFC-3986 re-encoded
  before HMAC, eliminating signature drift between equivalent encodings
  (`%2C` vs `,`, `+` vs `%20`). Invalid UTF-8 in the query string now
  returns HTTP 400 instead of bubbling out as a generic 500.
- **MEDIUM** `GET /config` uses `secret_store.redact_config` so every
  registered sensitive key class is masked, not just `virustotal_api_key`
  and `telemetry_fabric.headers`.
- **MEDIUM** In-memory signed-request nonce store is thread-safe.
  Compound `len + check + insert + popitem` is now serialized by a lock,
  and eviction is O(1) FIFO via `OrderedDict.popitem(last=False)`.
- **MEDIUM** `workspace_artifact_dir` re-normalizes the workspace ID and
  verifies the resolved path stays under `OUT_DIR`, even when the caller
  bypasses the route-level validators.
- **MEDIUM** Quarantine, replay-artifact, and quarantine-restore guards
  no longer call `expanduser()`. Tilde inputs are rejected up front.
- **MEDIUM** `WebhookDispatcher.purge_dlq` refuses an unfiltered delete
  unless the caller explicitly passes `confirm_purge_all=True`. A bare
  call used to wipe every row in every workspace.
- **MEDIUM** Webhook payloads are size-capped at 256 KiB (override:
  `SHADOWLAB_WEBHOOK_PAYLOAD_MAX_BYTES`). Oversized payloads are rejected
  at enqueue time so the on-disk delivery / DLQ tables stay bounded.
- **MEDIUM** `safe_child_path` performs a final `lstat()` to reject
  symlinks and Windows reparse points planted between path validation
  and file open.
- **LOW** `_extract_bearer_token` now parses `Authorization: Bearer ...`
  strictly per RFC 6750: single space delimiter, b64token charset, no
  tabs / CRLF / NUL.
- **LOW** AES-GCM secret-store decryption supports a hardened mode
  (`SHADOWLAB_REQUIRE_HARDENED_KDF=1`) that refuses the legacy 120k
  PBKDF2 iteration count, closing an iteration-oracle pathway after
  legacy ciphertext has been re-encrypted.
- **LOW** Webhook response read is bounded to 512 byte excerpt + 64 KiB
  drain budget so a hostile receiver cannot pin the dispatcher.
- **LOW** OIDC token rejection emits a `WARNING` log and a
  `shadowlab_oidc_rejections_total{reason=...}` Prometheus counter,
  bucketed by exception class.
- **HIGH** The three `/threat-intel/*` routes now require the
  analyst-or-admin role like every other intel route. Before this, a
  viewer (or any caller when `SHADOWLAB_REQUIRE_AUTH=false`) could drive
  unbounded outbound lookups to VirusTotal, MalwareBazaar, and YARAify,
  burning quota and scanning from inside the operator network. The
  authorization check runs before input validation so it holds even on
  malformed input.
- **HIGH** Server-supplied filesystem paths consumed by the desktop
  client (artifact open, delete, hash, integration export) now pass
  through a single `desktop/_safe_paths.py` chokepoint. Paths that do
  not resolve under a configured artifact root are rejected, UNC paths
  are refused outright, and the shell-open helper blocks executable and
  scripting suffixes. A compromised or MitM backend can no longer return
  an absolute path and ride the desktop's filesystem permissions to
  read, delete, or detonate arbitrary files. The realpath check is
  symmetric so a junction or symlink planted inside the artifact root is
  still blocked.
- **HIGH** The outbound allow-list no longer trusts a loopback IP that a
  public hostname resolves to. A name like `lvh.me`, `localtest.me`, or
  an attacker-controlled domain that answers `127.0.0.1` is rejected;
  loopback is only accepted when the URL hostname is itself a literal
  loopback name. This closes a DNS-rebinding path to the operator's own
  admin API that the earlier resolve-then-connect pinning did not cover.
- **MEDIUM** The desktop signed-request nonce is now 16 bytes of
  CSPRNG output (`secrets.token_hex`). The previous derivation,
  `sha256(timestamp:path:time_ns)` truncated to 24 hex characters, was
  predictable to anyone who knew the path and could sample the clock,
  and two parallel clients on one host could collide inside the same
  second and defeat the server-side replay guard.
- **MEDIUM** The Bandit gate no longer globally skips `B404`, `B603`,
  and `B607`. Those skips were masking every subprocess finding across
  the tree; subprocess risk now re-enters CI and is acknowledged per
  line only where it has been audited. `B602` (`shell=True`) stays in
  the gate so any future shell invocation fails the build.
- **MEDIUM** `.gitignore` and `.dockerignore` now exclude timestamped
  database backups (`*.db.bak`, `shadowlab.db.bak*`) and crypto or
  secret material (`*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.sqlite*`).
  A full copy of operator and incident data, such as a
  `shadowlab.db.bak-...` snapshot left in the working tree, can no
  longer be committed by accident or baked into a container image.
- **LOW** The test suite isolates the database to a throwaway temp file
  via `tests/conftest.py`. Running `pytest` previously read and wrote
  the live `shadowlab.db`, seeding it with fixture incidents that then
  surfaced in the desktop UI and letting real operator data flake the
  tests. Isolation is applied at collection time so connections opened
  during import also land in the sandbox.

### Changed (Detection scoring)

- **HIGH** Behavioral likelihood and incident severity are now gated on
  a true malicious indicator: a Defender malware verdict, a failed
  remediation, or cross-process injection telemetry. CPU, thread, TCP,
  and raw Sysmon volume are baseline-relative modifiers capped well
  below the MEDIUM threshold, so a clean production host scores near
  zero instead of floating into a permanent phantom MEDIUM incident on
  routine log volume. A window with no true signal is reported as a
  baseline telemetry snapshot rather than an incident.
- The per-workspace resource baseline is learned with an EWMA and only
  from benign windows, persisted as a small JSON document under
  `shadowlab_out`. A real incident can no longer shift the host's
  notion of normal and mask follow-on activity. Baseline write failures
  are advisory and never break scoring.
- `GET /history/telemetry` accepts an optional bounded `limit`, and the
  monitor scoring path threads `workspace_id` end to end so the right
  baseline is applied per workspace.

### Changed (Antivirus pipeline)

- **CRITICAL** Fusion layer enforces a consensus model. Providers are
  split into `_HARD_PROVIDERS` (signature-based: `aegis_core`,
  `sentinel_cli`, `cloud_intel`) and `_SOFT_PROVIDERS` (heuristic:
  `behavioural`, `yara_x`, `cloud_sandbox`). A single hard hit is
  sufficient to escalate to malicious; soft hits require corroboration
  from a second soft engine. A binary signed by a trusted publisher
  can never reach `malicious` via the soft path alone, and never
  triggers `auto_quarantine_ready` without a hard hit.
- **CRITICAL** `BehaviouralAnalyzer` no longer escalates `suspicious`
  to `infected` on its own. Heuristic findings always contribute as
  `suspicious` so the fusion layer can weight them against other
  engines.
- **CRITICAL** `YaraXProvider.scan_file` now passes a context dict that
  carries `signature_status`, `signer_subject`, `trusted_publisher`,
  and `filepath` into `plugins/yara_scanner`. The trusted-path-with-
  valid-signature suppression inside the scanner is no longer dead code.
- **HIGH** New `services/antivirus/authenticode.py` runs Authenticode
  in-process via `WinVerifyTrust` (ctypes) with an LRU cache keyed by
  `(path, mtime, size)`. The previous PowerShell-per-scan code path
  is replaced. Trusted publishers (Microsoft, Google, Mozilla, Apple,
  Adobe, Intel, NVIDIA, AMD, Oracle, IBM, Valve, Amazon, OpenSSL)
  are recognised by signer subject; operators can extend the list via
  `SHADOWLAB_AV_TRUSTED_PUBLISHERS`.
- **HIGH** `static_pe_service._signature_risk` returns a negative score
  delta (`-30`) for a trusted-publisher signature. A clamp at zero
  ensures the resulting score never goes negative. The "helper / stub /
  payload / dropper" filename penalty is gated on the publisher NOT
  being trusted, so legitimate Microsoft updaters and WebView2 stubs
  no longer get penalised on their filename alone.
- **HIGH** `SUSPICIOUS_IMPORTS` is split into tier-1 (NT syscalls,
  dynamic-code-trust probes; full weight) and tier-2 (`VirtualAlloc`,
  `VirtualProtect`, `AmsiScanBuffer`, `ShellExecute`, etc.; only
  scored when paired with an RWX section, high entropy, or a
  suspicious section name). Modern Windows runtimes (V8 JIT, .NET CLR,
  Electron) no longer accumulate heuristic score from imports alone.
- **HIGH** VirusTotal scoring requires BOTH a minimum number of malicious
  detections (default 5) AND a minimum detection ratio (default 10% of
  active scanners). Borderline signals contribute a low-confidence
  +8 instead of escalating the provider verdict. Tunable via
  `SHADOWLAB_VT_MIN_MALICIOUS` and `SHADOWLAB_VT_MIN_RATIO`.
- **HIGH** MalwareBazaar bare hash matches no longer fire a full +50
  score. Only attributions with a real malware family (`signature`
  field) escalate; metadata-only hits contribute +10.
- **HIGH** YARA escalation gate: a YARA-active match becomes `infected`
  only when the aggregate score is at least 30 AND the maximum
  per-rule severity is at least `high`. Trusted-publisher binaries
  cannot reach `infected` from YARA unless a `critical`-severity
  rule fires.

### Changed (Other)

- `AntivirusService.scan_file` refuses tilde-expanded paths.
- `pefile` parsing is bounded: at most 4096 imports and 96 sections
  are inspected, preventing pathological PE samples from pinning the
  scanner.
- Per-provider score floor in fusion lowered from 40 to 20 so a single
  infected provider with an internally-low score no longer auto-pushes
  the fused severity into the `high` band.
- Bug-report and feature-request issue templates request the ShadowLab
  version and policy profile up front.
- Pull-request template includes a secrets-and-tokens checkbox and a
  security-impact prompt for sensitive code paths.
- `plugins/rules/YARA_VALIDATION.md` no longer contains a hardcoded
  developer path; pack sources are documented relative to repo root.
- `config/antivirus/freshclam.conf` uses a `__SHADOWLAB_ROOT__`
  placeholder instead of an absolute developer path.
- `config/telemetry-fabric-builder.yaml` ships with a relative
  `output_path`.

### Removed

- `honey/passwords.txt` and `canary_files/*` decoy fixtures have been
  removed from the repository. Decoy material is regenerated at runtime
  instead of being version-controlled.

### Documentation

- `docs/USAGE_GUIDE.md` documents the expanded signed-mutation set
  (`POST`, `PUT`, `PATCH`, `DELETE`) and the upgrade compatibility note
  for clients that still only sign `POST` / `PATCH` / `DELETE`.
- `plugins/rules/YARA_VALIDATION.md` documents pack sources, suppressed
  rules with reasons, and verified-pack-health metrics in tables.

## Older Releases

Earlier releases predate this changelog. Historical release notes live
in the repository's tag annotations and in `docs/ENTERPRISE_ROADMAP.md`.
