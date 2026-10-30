# Runtime client binding

Base: namib-project/libcoap-rs `0dbf5d33eae294cd16ff5111e6d992f087fb0eae`.
The libcoap submodule pins the controlled-runtime fork of upstream v4.3.5b (`851533c3`). `d23c588856e21a53573719070e5e7ceb46fc8ccb` is fork history, not the upstream basis.
Both repositories retain their upstream BSD licenses and history.

`runtime-io` adds `controlled::Client`: one !Send context/session owner, supplied
nonblocking I/O, native Block1/2/BERT and Observe, finite resource bounds, DTLS
PSK/PKI, OSCORE reservation/replay callbacks, cancellation and owned cleanup.
All wire encoding, exchange state and cryptography remain in libcoap/OpenSSL.
Callbacks catch Rust panics at the FFI boundary. A handshake NACK can have no PDU;
this is represented by an empty token without dereferencing a null pointer.
Private configuration, keys and upload buffers are zeroized.

The feature builds fixed vendored libcoap with CMake and vendored OpenSSL, with
TCP, DTLS, OSCORE and thread locking enabled. It does not search for a system
libcoap or silently switch engines. The caller supplies already verified TLS
streams for reliable CoAP. Native DTLS passes the full DER chain to its verifier.
macOS sockaddr lengths and portable non-Linux epoll bindings are corrected;
num-derive is updated for current Rust. The package metadata identifies libcoap
4.3.5b rather than the former 4.3.1 submodule.

The embedding application's independent fixtures cover request/response,
streaming, multicast, credential security, malformed/negative results, delivery
bounds, context persistence, cancellation and shutdown. Cross-platform release
packaging must separately validate the platform compiler, CMake and static link.

## Resource simplification (2026-09-14)

Keep the native transmit MTU instead of deriving it from the receive allocation bound. Outgoing materialized body bounds are independent of PDU receive bounds. Native blockwise/CSM negotiation, parser protections and checked lengths remain unchanged. Validation coverage: Runtime UDP/TCP/TLS/DTLS, blockwise, Observe and multicast interoperability suite.

## Windows socket ABI (2026-09-18)

The Windows build uses the Winsock structures from `windows-sys` instead of Unix
libc socket types. Bindgen is told that these external structures implement Copy,
so native address unions retain their correct representation. IPv4, IPv6, scope
IDs, flow information and ports use the Windows field layout. CoAP code and NACK
values account for MSVC's signed C enums without changing the native protocol.
The native Windows address roundtrip regression passed for IPv4 and scoped IPv6.

## Windows supplied-I/O polling (2026-09-18)

The native submodule handles Winsock's rejection of empty descriptor sets while
retaining bounded callback polling and the caller-owned network transport.
`controlled_io_tests::supplied_io_polls_without_native_socket_descriptors` covers
UDP and TCP clients with only supplied callbacks. The product's oversized reliable
frame fixture additionally checks real TCP startup and immediate parser rejection.

## Streamed bodies that cannot complete (2026-10-03)

The native submodule reports a streamed Block2 body it cannot complete (ETag
change, missing ETag, Content-Format change, block tracking overflow, failed
continuation request) as `COAP_NACK_BODY_INCOMPLETE` with the request's own
token, instead of restarting the request unasked or stopping silently.
`controlled_io_tests::a_streamed_body_that_cannot_complete_fails_its_own_request_without_another`
answers a POST blockwise by hand and checks the NACK, that only the first block
is delivered and that no further request is written;
`a_body_whose_blocks_outrun_tracking_fails_its_own_request_without_another`
skips a block in every answer until the native received-range tracking
overflows. Both fail without the native patch. A supplied write error stops the
client, so a continuation request that cannot be sent has no case of its own.

## OSCORE context presence

The native submodule preserves absent versus present-empty ID Context in KDF
info, option encoding and recipient-context lookup. Its CUnit regression
`t_oscore_context_presence` fails on the previous pin and passes after the fix;
all 178 native tests pass on macOS arm64 with OpenSSL. The Rust binding keeps
configuration bytes intact; the embedding caller supplies quoted hex fields,
including empty IDs, and preserves context presence in persistent-state identity.

## External event-loop deadline (W11g)

`controlled::Client::prepare_wait` exposes the wait libcoap computes through
`coap_io_prepare_io` or `coap_io_prepare_epoll`, according to the compiled
engine's support. A zero native wait means no timer deadline. Preparing also
processes due timers, as the native external event-loop contract specifies.
The caller wakes on supplied I/O and the next native deadline instead of
polling at a fixed interval. Without the native deadline, a caller sleeping
only for arrivals stalls retransmissions and DTLS when the peer is silent.
No timer arithmetic or native context pointer is exposed or duplicated.

`controlled_io_tests::external_wait_preserves_a_silent_peers_retransmission`
sends a CON, waits once for the returned deadline without input, and verifies
that the next native pass retransmits the same message. Boundless additionally
tests this through its supplied UDP transport and sleeping worker.

## Native retransmission capacity

Replace the controlled client's independent retry and ACK-timeout quotas with
`controlled::retransmit_ack_timeout_maximum_ms`, derived from the bundled
libcoap's signed `MAX_TRANSMIT_WAIT` intermediate before division. In the native
setter domain (at least one retransmission and a 1,000 ms ACK timeout), this
joint bound also protects the Q6 conversion, all randomized timeout calculations,
the unsigned-char counter, every shift and the derived waits. No native setter
is changed. The client checks the domain and capacity before allocating native
state; callers use the same function for their own typed admission failure.

On macOS arm64,
`controlled_io_tests::representable_retransmission_parameters_reach_the_native_session`
fails at the previous pin with `invalid client limits` and passes with this
patch: nine retries at 1,000 ms and one retry at 477,218 ms reach the native
session unchanged.
`native_retransmission_arithmetic_fits_at_each_joint_boundary` checks every
admissible count's exact boundary and its first unrepresentable timeout,
and calls the native `coap_calc_timeout` for all 256 random values at each
boundary, checking the shifted timeout and its millisecond conversion.
The scoped controlled-I/O run passed, including the existing streamed-body,
PSK and supplied-I/O regressions. Other supported hosts retain their platform gates.

## Configured PDU capacity (W11d)

The controlled client accepts the native CSM receive domain, 64 through
u32::MAX bytes, without an independent 16 MiB ceiling. Request options use
the full configured PDU allowance rather than half of it. The native submodule
checks supplied-I/O TCP PDUs only against the runtime receive maximum;
non-supplied-I/O clients retain the compile-time default.

`supplied_tcp_pdu_uses_the_runtime_receive_maximum` supplies independently
encoded TCP responses: a payload above 8 MiB + 256 bytes within a 9 MiB runtime
maximum is delivered whole, and one above that maximum ends the native client
without delivery. The corrected regression fails on the previous native pin
and passes with this patch on macOS arm64. Boundless additionally tests its
configured PDU and outgoing option checkpoint.

## Rule 20: partial quota revert of 55f1dae

The driver-plan Rule 20 fork audit requires removing program-chosen option and
PSK quotas while retaining the controlled client and its other behavior. At
`a3db252`, `libcoap/src/controlled.rs:147,380` imposes an outgoing option-count
quota, and `:235` refuses identities above 128 bytes and keys above 64 bytes.
Those counts are not native capacities. Receive-side option/allocation
protection, encoded-message checks, short nonempty PSKs, OSCORE, native numeric
ranges and the other controlled APIs remain in place.

The native OpenSSL implementation supplies the precedent and the boundary:
`src/coap_openssl.c:827-850` reserves an identity NUL and otherwise truncates to
its callback buffer lengths. OpenSSL's `ssl/statem/statem_clnt.c` PSK preamble
passes `PSK_MAX_IDENTITY_LEN` identity buffer bytes and `PSK_MAX_PSK_LEN` key
bytes (3.5.5:3030-3051; 3.6.3:3072-3093). Accordingly the controlled binding
exports `PSK_IDENTITY_MAXIMUM_BYTES` and `PSK_KEY_MAXIMUM_BYTES`, derived by
bindgen from the exact OpenSSL headers used for the native build: currently
255 identity payload bytes and 512 key bytes. `Client::new` checks both before
creating its native PSK session and names the exceeded native capacity rather
than letting the callback truncate. No native submodule patch is needed.
`Limits::maximum_options` now governs received options only; it has no fixed
128-entry configuration ceiling and never limits an outgoing request.

On macOS arm64, adding the outgoing 129-option wire regression and the real
DTLS peer regression to `a3db252` produced the two expected refusals (exit 101).
After this patch `cargo test -p libcoap-rs --features runtime-io --locked --
--test-threads=1` passes all 33 unit, integration and documentation tests:

- `outgoing_options_are_not_limited_by_the_receive_option_count` independently
  decodes the written packet and verifies every caller option, alongside the
  native Request-Tag.
- `psk_native_capacity_reaches_the_peer_without_truncation` establishes DTLS
  with 129/65-byte credentials and at the exported identity/key boundaries.
  The peer selects a key only for the complete identity; Finished proves use
  of the complete key.
- `psk_excess_names_the_native_capacity_before_native_session_creation` checks
  both first excessive lengths. `psk_accepts_short_nonempty_protocol_keys`
  retains short-key coverage and no longer asserts the removed 64-byte quota.
- `the_supplied_receive_option_limit_still_protects_the_callback` admits 129
  received options at that configured bound and refuses 130.

The macOS `libcoap-sys` own tests are blocked by existing `sockaddr_in` and
`sockaddr_in6` fixture initializers missing `sin_len`/`sin6_len`
(`libcoap-sys/src/lib.rs:548,568`); the same command fails with exit 101 after
restoring the original sys build script and wrapper. Whole-fork formatting
also reports the original import ordering in `libcoap/src/context.rs`; changed
Rust files pass the formatter. These unrelated baseline defects are not repaired
by this patch. Other supported hosts retain their separate platform gates.

## Rule 20: native OSCORE configuration and replay admission

The owner's 2026-10-24 decision removes the remaining OSCORE quotas from
`55f1dae`. At `59b54d92`, `libcoap/src/controlled.rs:207` refuses configuration
above 4,096 bytes or more than 16 replay entries. Neither number is a native
capacity. The bundled libcoap parser consumes a length-delimited configuration
(`src/coap_oscore.c:1951-2114`) and grows its recipient array for each entry
(`:1989-2008`); native context derivation creates each recipient
(`src/oscore/oscore_context.c:582-589`). The existing
`coap_context_restore_runtime_replay` walks those native recipients and refuses
an unknown ID (`src/coap_oscore.c:2343-2361`). This native implementation is the
precedent; no new API or native patch is needed.

`controlled::Client::new` delegates configuration parsing and each replay
restore to those APIs. Its OSCORE 40-bit sender-sequence admission check stays,
as do native configuration errors and unknown-recipient restore failures.

On macOS arm64, both single-test regressions fail at `59b54d92` with
`invalid OSCORE configuration bound` (exit 101) and pass after this change
(exit 0). `oscore_configuration_reaches_the_native_parser_without_a_byte_quota`
first proves native parsing of a configuration above 4,096 bytes using a
2,048-byte HKDF salt, then proves native key derivation/session creation at the
last 40-bit sender sequence and refusal at 2^40.
`oscore_restores_all_configured_native_recipients` restores 17 configured native
recipients; removing the last recipient still produces the native
`OSCORE replay restore failed` refusal. The `Client::new` admission path is the
single configuration/restore check point; it owns the native context/session and
exposes no alternate controlled-client constructor.

## Native CSM behavior (owner decision, 2026-10-24)

Remove `55f1dae`'s unexplained five-second CSM override from
`libcoap/src/controlled.rs:200` at `330e431`. The native implementation creates
contexts with its own CSM timer (`src/coap_net.c:707-709`), computes the pending
CSM wait in its event-loop preparation (`src/coap_io.c:1496-1511`) and processes
peer CSM in `src/coap_net.c:3780-3855`. `controlled::Client::new` now leaves that
native behavior intact for every supplied-I/O client. Boundless's own
establishment bound governs how long its connection setup may wait. No new API,
native patch or replacement timer is introduced.

On macOS arm64,
`reliable_client_keeps_the_native_csm_timer_and_accepts_peer_csm` fails before
removal (exit 101, controlled 5,000 ms versus native 1,000 ms) and passes after
(exit 0). It compares the controlled context with a freshly created native
context, checks that `prepare_wait` exposes the native pending CSM deadline,
and supplies an independently encoded peer CSM that makes `ready()` true.

## Rust 1.97 strict tooling (Boundless #325)

At `9fe6115a9cf4ab5a8f4704e28cad95d3e0aa5671`, the strict Clippy command
below exits 101 on five hidden `Version` lifetimes in the sys build systems.
Running the same command without `-- -D warnings` also exits 101: it exposes
the four integration-test `never_loop` sites and the remaining library/test
warnings hidden by that first build-script failure. The declared formatter is
`nightly-2026-01-31` in `devenv.nix`; its check exits 1 on `context.rs` import
ordering. The issue's separate `controlled.rs` formatting difference does not
reproduce at this pin. No formatter configuration or lint level is weakened.

Upstream `namib-project/libcoap-rs` main at
`0dbf5d33eae294cd16ff5111e6d992f087fb0eae` still has the same hidden build-system
lifetimes, first-response loops, boxed recipient strings, private unused resource
methods and reference-to-raw-slice conversions. There is no newer upstream fix
to reuse for these sites. The repair retains the library's existing APIs and
native conversions:

- Spell the ten borrowed `Version`, `Ref`, `RefMut` and `Iter` lifetimes as `'_`.
- Replace the four loops that unconditionally return on their first response
  with `if let Some(...) = ...next()`, keeping both the outer I/O wait and
  server join. Remove the four no-op response-slice `as_ref()` calls.
- Remove two unused methods from the private, unexported resource trait and
  their implementations; this also removes the unnecessary parentheses and
  return. Remove the unused `mut` on the attribute helper's existing mutable
  borrow, retaining the borrow kind and its failure behavior.
- Store OSCORE recipient `String`s directly. Their byte buffers stay in place
  when the vector grows; duplicate checks, native calls, removal errors and
  cleanup ordering stay the same.
- Reconstruct owned PSK boxes with `ptr::slice_from_raw_parts_mut`, retaining
  the identity's null check and the original lengths and ownership transfer.
- Use byte-string defaults and explicit lazy null-pointer branches for URI
  components. Fix doc-list indentation, doc-comment spacing and import ordering.

One lint class is a portability false positive and has targeted `allow`
attributes with reasons beside them:

- `clippy::unnecessary_cast`: bindgen emits signed C enums on MSVC and unsigned
  C enums on this host. Keep the original bit-preserving `as u32` conversions
  on `CoapSessionState`, `CoapUriScheme`, `CoapProtocol`, their raw decoding
  methods, request/response/message-type decoding, the controlled NACK/session
  callbacks and their native-code comparisons in tests. Each attribute covers
  only the affected enum, conversion implementation, method, helper or local
  NACK construction; no module-wide allowance is added.

The block-mode flags pass directly as `u32`; `clippy::useless_conversion` is
not a portability false positive. The minimum supported native libcoap is
4.3.5, and 4.3.5, 4.3.5a, 4.3.5b and the ESP-IDF example's locked component
4.3.5~3 all declare a `uint32_t` block-mode parameter. The `uint8_t` signature
belongs to 4.3.4, below the supported minimum. Review of `7b5a836` corrected
the earlier rationale and removed both the redundant checked conversion and
its local allowance. For supported versions, the identity conversion could
not fail; passing the same flags directly preserves caller-visible behavior.

`recipient_growth_keeps_duplicate_and_removal_results` exercises native
recipient addition/deletion across vector growth, the initial recipient's
duplicate refusal, and the unchanged no-context, duplicate and missing-recipient
errors. `raw_psk_roundtrip_keeps_absent_empty_and_binary_values` checks ownership
round trips for absent, present-empty and binary identities and empty/binary
keys. The existing UDP, TCP and DTLS integration assertions still check the
first response and the server's completion. No lock or poisoning path changes.

Validation on macOS arm64, with `CARGO_INCREMENTAL=0` and compilations/tests
admitted through `build-slot`:

| Command | Before | After |
| --- | --- | --- |
| `cargo +1.97.0 clippy -p libcoap-rs --lib --tests --no-default-features --features runtime-io -- -D warnings` | 101 | 0 |
| `cargo +nightly-2026-01-31 fmt --all --check` | 1 | 0 |

The runtime regression command is `cargo +1.97.0 test -p libcoap-rs
--no-default-features --features runtime-io --locked -- --test-threads=1`.

## Received Reset target (W5-D7)

`controlled::Event::Received(PeerMessage)` reports an actual received datagram
Reset before libcoap changes its native state. `PeerMessage` has private fields,
no setters, and a single constructor in the native received callback. Read-only
getters expose the received type, code, MID, token, options and payload, separately
from `Target::Application(app_token)`, `Internal(Probe)` or `Unmatched`.
The response and received callbacks share one bounded field parser. Registration
is removed before context destruction, like the other controlled handlers.

The native submodule is `c859ba15ac9e42944e746f21c4d4c29aea151cbb`;
its shared resolver restores the application token of later Block1/Block2 PDUs
without treating the sent PDU as peer evidence. The supplied-I/O regressions
`a_reset_names_the_request_it_answers_before_its_nack`,
`a_reset_of_a_later_block2_block_names_the_application_token`,
`a_reset_of_a_later_block1_block_names_the_application_token` and
`an_unknown_reset_names_no_request` pass on macOS arm64, as does the complete
Rust package suite with `--no-default-features --features runtime-io`, including
doctests. Native CUnit coverage is recorded in its own PATCHES.md.


## Preserve native teardown output (F7)

Start from upstream 0dbf5d33 `libcoap/src/session/client.rs`'s
`CoapClientSessionInner::drop`: disable callbacks that access a partially dropped
session, then release it while native I/O remains usable. The supplied-I/O Client
keeps those callback removals and no longer marks an otherwise healthy I/O state
failed before releasing the session/context. libcoap's upstream OpenSSL
`coap_dtls_free_session` owns SSL_shutdown and its close_notify write. No different
teardown policy is needed. An already failed callback state stays failed, retaining
the recorded panic/error boundary.

Regression: `drop_sends_native_close_notify_to_the_dtls_peer` drives a real
DTLS handshake and client Drop, then waits for the server's DTLS-closed event:
its peer must receive and decrypt the native close_notify.

## Native CSM fallback (F8)

The libcoap gitlink includes the native `coap_client_delay_first` restoration
to upstream 851533c3: supplied I/O keeps csm_not_seen fallback when a direct
pre-ready request reaches the CSM timeout. No differing policy is required.
The native PATCHES.md names the CUnit request-path regression and its result.

On macOS arm64 with consumer Rust 1.97.0, the consumer-feature package suite
(`--no-default-features --features runtime-io`, single test thread) and strict
lib/tests Clippy pass, including the peer-observed close_notify regression.
Workspace/default feature aggregation requests native features deliberately
disabled by runtime-io and cannot build that combination. Stable workspace fmt
reports existing unformatted received-Reset code outside this change; the new
regression is formatted and unrelated formatting is left untouched to keep the
upstream restoration minimal.

## Consumer native-I/O admission during normal close (review B F7)

The upstream source remains 0dbf5d33 `session/client.rs:283-311`: native
release may perform I/O after semantic callbacks are disabled. The controlled
client keeps that release and its existing error/panic latch unchanged.
`controlled::write` maps WouldBlock to a native retry indication, while a
real error or panic latches failure; returning WouldBlock from a final Drop
write cannot cause a later poll after native state is freed. A supplied
consumer must therefore keep healthy native I/O usable during a normal-close
race, and admit final-release output to its bounded pump before release
returns. Boundless now does both at Adapter::write: command admission remains
closed, normal native writes stay nonfatal, and only final release waits for
bounded capacity, subject to inherited cancellation/deadline and pump failure.
There is no additional fork runtime mechanism or native retry policy.

Boundless's gated, real OpenSSL DTLS regressions close while a native timer
retransmission is about to write, and while the pump is held with all sixteen
output slots full during real native release. Both require the peer's decrypted
close_notify, the original Program end and native-owner/pump joins. They fail
on the reviewed consumer before its correction. The fork's healthy-Drop peer
regression and real error/panic latching remain unchanged.

## Received reliable ending messages (W5-D7 remainder)

Upstream libcoap `851533c3::handle_signaling` discards Release/Abort fields at
disconnect; its public handlers do not expose that PDU. `d23c5888` is fork
history, not the upstream basis. The native patch invokes the existing
received hook before the unchanged disconnect. The controlled projection adds
`Target::Session` and `PeerMessage::peer()` from the actual native remote
address at the sole received constructor, using the existing field reader.
No sent PDU or alternate parser becomes peer evidence.

`received_signaling_keeps_fields_and_peer_before_native_disconnect` supplies
independently encoded Release/Abort, with zero and two outstanding requests,
and checks exact raw fields, peer, the hook before native NACKs and the actual
disconnect. Existing later Block1/2 Reset/probe/collision behavior is retained.
Validation: macOS arm64, all 21 controlled-I/O regressions pass, including
zero/two-pending Release/Abort, later Block1/Block2 Reset resolution, healthy
Drop, native timer and real error/panic latching. Strict Clippy of libcoap-rs
(`--lib --tests`, runtime-io) passes. Native checkpoint sensitivity is recorded
in the submodule PATCHES.md. The native peer getter is a snapshot: supplied
stream labels and routed datagram relay addresses are not necessarily observed
target peers; the embedding transport owner decides whether to publish it.

## Multicast received-source acceptance (W5-D7 amendment)

`a_multicast_non_reset_keeps_its_individual_source_snapshot` sends an actual
native NON request to a multicast group through supplied I/O, then supplies a
Reset from an individual source. The existing native received hook reports
that source in the immutable `PeerMessage`, distinct from the group address.
The target remains Unmatched: `coap_runtime_classify_rst` resolves Application
only from a queued CON, and multicast requests and their Block2 copies are NON.
No NON correlation or adapter publication path is added. This replaces the
consumer's impossible published-multicast-Reset acceptance assertion.

Validation: macOS arm64, the focused native multicast hook regression passes;
combined libcoap-rs/libcoap-sys strict lib/test Clippy passes.

## BSD socket lengths in sys test fixtures

The sys-only `tests::coap_address_from_socketaddr` helper initialized libc
`sockaddr_in` and `sockaddr_in6` without their BSD length fields. On macOS
arm64 the combined binding/sys `--lib --tests` Clippy check failed with E0063
for `sin_len` and `sin6_len`, before checking or running the test target.
Use the same conditional length initialization as the existing production
`CoapAddress::from` conversion in `libcoap/src/types.rs`. Both test address
families pass through this one helper. Production address conversion and the
native submodule are unchanged. This is a separate test portability repair.

Validation: macOS arm64, combined libcoap-rs/libcoap-sys strict lib/test Clippy
passes, and the repaired helper runs the native client/server exchange
(`tests::test_coap_client_server_basic`) successfully.
