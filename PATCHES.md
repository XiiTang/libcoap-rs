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
