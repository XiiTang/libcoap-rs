# Runtime client binding

Base: namib-project/libcoap-rs `0dbf5d33eae294cd16ff5111e6d992f087fb0eae`.
The libcoap submodule pins the controlled-runtime fork of upstream v4.3.5b (`d23c588856e21a53573719070e5e7ceb46fc8ccb`).
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
