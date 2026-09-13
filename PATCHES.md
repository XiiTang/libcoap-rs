# Runtime client binding

Base: namib-project/libcoap-rs `0dbf5d33eae294cd16ff5111e6d992f087fb0eae`.
The libcoap submodule pins the controlled-runtime fork of upstream v4.3.5b (`2bbd80b34b89fb07e3389b69b32112def23bd5cf`).
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
