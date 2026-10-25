// SPDX-License-Identifier: BSD-2-Clause
//! A single-thread-owned client using supplied I/O. The native engine owns all
//! CoAP exchanges, retransmission, Observe, Block1/2, BERT, DTLS and OSCORE.
use std::{
    ffi::{c_void, CString},
    io,
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    ptr,
    rc::Rc,
};

use libcoap_sys::*;
use zeroize::Zeroizing;

use crate::{context::ensure_coap_started, types::CoapAddress};

/// Callbacks run synchronously on the client's owner thread. They must not
/// re-enter the client. A false event/persistence result permanently stops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseDecision {
    Accept,
    Reject,
    Stop,
}
pub trait Callbacks {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)>;
    fn write(&mut self, bytes: &[u8], peer: Option<SocketAddr>) -> io::Result<usize>;
    fn event(&mut self, event: Event) -> bool;
    fn response(&mut self, event: Event) -> ResponseDecision {
        if self.event(event) {
            ResponseDecision::Accept
        } else {
            ResponseDecision::Stop
        }
    }
    fn verify(&mut self, _chain: &[&[u8]]) -> bool {
        false
    }
    fn reserve_sender(&mut self, _next: u64) -> bool {
        false
    }
    fn save_replay(&mut self, _id: &[u8], _seq: u64, _window: u64, _initial: u8) -> bool {
        false
    }
}
#[derive(Debug)]
pub enum Event {
    Response {
        token: Vec<u8>,
        code: u8,
        message_type: u8,
        mid: i32,
        options: Vec<(u16, Vec<u8>)>,
        payload: Vec<u8>,
        offset: usize,
        total: usize,
        more: bool,
        peer: SocketAddr,
    },
    Nack {
        token: Vec<u8>,
        reason: u32,
        mid: i32,
    },
    Session {
        code: u32,
    },
}
pub enum Security {
    None,
    Psk {
        identity: Zeroizing<Vec<u8>>,
        key: Zeroizing<Vec<u8>>,
        sni: String,
    },
    Certificate {
        chain: Zeroizing<Vec<u8>>,
        key: Zeroizing<Vec<u8>>,
        sni: String,
    },
}
pub struct Oscore {
    pub configuration: Zeroizing<Vec<u8>>,
    pub sender_next: u64,
    pub replay: Vec<(Vec<u8>, u64, u64, u8)>,
}
pub struct Limits {
    pub maximum_pdu: usize,
    pub maximum_body: usize,
    /// Maximum received option count; outgoing requests have no count quota.
    pub maximum_options: usize,
    pub maximum_retransmit: u16,
    pub ack_timeout_ms: u32,
}

/// Maximum identity payload bytes in the bundled OpenSSL PSK callback. The
/// native callback reserves one byte of PSK_MAX_IDENTITY_LEN for a NUL.
pub const PSK_IDENTITY_MAXIMUM_BYTES: usize = COAP_RUNTIME_PSK_IDENTITY_MAXIMUM_BYTES as usize;
/// Maximum key bytes in the bundled OpenSSL PSK callback (PSK_MAX_PSK_LEN).
pub const PSK_KEY_MAXIMUM_BYTES: usize = COAP_RUNTIME_PSK_KEY_MAXIMUM_BYTES as usize;

/// Largest ACK timeout in milliseconds representable at this retransmission
/// count by the bundled native engine. Zero means no timeout in its domain.
/// The native setter domain is maximum >= 1 and ack_timeout_ms >= 1000.
///
/// coap_session_internal.h's MAX_TRANSMIT_WAIT multiplies
/// `ack_ms * (2^(maximum + 1) - 1) * 1500` as signed C int *before* dividing
/// by 1_000_000. This is the tightest bound in that domain, not a retry quota.
/// It implies maximum <= 9 and ack_ms <= 477_218, hence:
/// - the unsigned-char retry counter and every signed `1 << ...` fit;
/// - coap_net.c's Q6 ACK conversion fits uint16_t (at most 30_542);
/// - all 256 random factors in coap_calc_timeout fit its unsigned intermediates;
/// - timeout << retransmit_cnt, including its unsigned `* 1000` debug expression,
///   fits unsigned int (the shifted timeout is below 1_440_000 ticks);
/// - transmit span/wait, processing delay, RTT and exchange/NON lifetimes fit
///   signed int; their millisecond ticks fit the bundled 64-bit coap_tick_t.
///
/// The runtime-io build fixes ACK_RANDOM_FACTOR at its native default 1.500,
/// Q6/8-bit random arithmetic and 1000 ticks/second on its supported hosts.
pub fn retransmit_ack_timeout_maximum_ms(maximum: u16) -> u32 {
    // A signed C `1 << (maximum + 1)` must not reach its sign bit. This
    // also excludes counts beyond the unsigned-char counter's capacity.
    let shift = u32::from(maximum) + 1;
    if maximum == 0 || shift >= std::ffi::c_int::BITS - 1 {
        return 0;
    }
    let wait_factor = ((1u64 << shift) - 1) * 1500;
    (std::ffi::c_int::MAX as u64 / wait_factor) as u32
}
struct State {
    callbacks: Box<dyn Callbacks>,
    failed: bool,
    maximum_pdu: usize,
    maximum_options: usize,
}
pub struct Client {
    context: *mut coap_context_t,
    session: *mut coap_session_t,
    state: Box<State>,
    maximum_body: usize,
    peer: SocketAddr,
    _security: Security,
    _thread: PhantomData<Rc<()>>,
}
impl Client {
    pub fn new(
        peer: SocketAddr,
        tcp: bool,
        security: Security,
        oscore: Option<Oscore>,
        limits: Limits,
        callbacks: Box<dyn Callbacks>,
    ) -> Result<Self, &'static str> {
        if !(64..=u32::MAX as usize).contains(&limits.maximum_pdu) || limits.maximum_body == 0 {
            return Err("invalid client limits");
        }
        if limits.ack_timeout_ms < 1000
            || limits.ack_timeout_ms > retransmit_ack_timeout_maximum_ms(limits.maximum_retransmit)
        {
            return Err("retransmission parameters exceed native capacity or are outside the native setter domain");
        }
        if tcp && !matches!(security, Security::None) {
            return Err("supply already verified TLS over the TCP transport");
        }
        match &security {
            Security::Psk { sni, .. } | Security::Certificate { sni, .. } if sni.as_bytes().contains(&0) => {
                return Err("invalid SNI");
            },
            _ => {},
        }
        ensure_coap_started();
        // All native objects and borrowed pointers are owned by this !Send client.
        unsafe {
            let context = coap_new_context(ptr::null());
            if context.is_null() {
                return Err("context allocation failed");
            }
            let state = Box::new(State {
                callbacks,
                failed: false,
                maximum_pdu: limits.maximum_pdu,
                maximum_options: limits.maximum_options,
            });
            let mut client = Self {
                context,
                session: ptr::null_mut(),
                state,
                maximum_body: limits.maximum_body,
                peer,
                _security: security,
                _thread: PhantomData,
            };
            let data = (&mut *client.state as *mut State).cast();
            coap_set_app_data(context, data);
            if coap_context_set_runtime_io(context, data, Some(read), Some(write), limits.maximum_pdu) != 1 {
                return Err("controlled I/O unavailable");
            }
            coap_context_set_block_mode(context, COAP_BLOCK_USE_LIBCOAP);
            coap_context_set_csm_max_message_size(context, limits.maximum_pdu as u32);
            coap_register_response_handler(context, Some(response));
            coap_register_nack_handler(context, Some(nack));
            coap_register_event_handler(context, Some(event));
            coap_context_set_runtime_verify(context, Some(verify));
            let mut conf = ptr::null_mut();
            if let Some(oscore) = &oscore {
                if oscore.sender_next >= (1u64 << 40) {
                    return Err("invalid OSCORE configuration bound");
                }
                conf = coap_new_oscore_conf(
                    coap_str_const_t {
                        length: oscore.configuration.len(),
                        s: oscore.configuration.as_ptr(),
                    },
                    Some(reserve),
                    data,
                    oscore.sender_next,
                );
                if conf.is_null() {
                    return Err("OSCORE configuration rejected");
                }
                coap_context_set_runtime_replay(context, Some(replay));
            }
            let address = CoapAddress::from(peer);
            let proto = if tcp {
                coap_proto_t_COAP_PROTO_TCP
            } else if matches!(client._security, Security::None) {
                coap_proto_t_COAP_PROTO_UDP
            } else {
                coap_proto_t_COAP_PROTO_DTLS
            };
            client.session = match &client._security {
                Security::None => {
                    if conf.is_null() {
                        coap_new_client_session(context, ptr::null(), address.as_raw_address(), proto)
                    } else {
                        coap_new_client_session_oscore(context, ptr::null(), address.as_raw_address(), proto, conf)
                    }
                },
                Security::Psk { identity, key, sni } => {
                    let refusal = if identity.len() > PSK_IDENTITY_MAXIMUM_BYTES {
                        Some("PSK identity exceeds native PSK_MAX_IDENTITY_LEN minus its NUL terminator")
                    } else if key.len() > PSK_KEY_MAXIMUM_BYTES {
                        Some("PSK key exceeds native PSK_MAX_PSK_LEN")
                    } else if identity.is_empty() || key.is_empty() {
                        Some("invalid PSK bounds")
                    } else {
                        None
                    };
                    if let Some(refusal) = refusal {
                        if !conf.is_null() {
                            coap_delete_oscore_conf(conf);
                        }
                        return Err(refusal);
                    }
                    let sni = CString::new(sni.as_str()).map_err(|_| "invalid SNI")?;
                    let mut psk: coap_dtls_cpsk_t = std::mem::zeroed();
                    psk.version = COAP_DTLS_CPSK_SETUP_VERSION as u8;
                    psk.client_sni = sni.as_ptr().cast_mut();
                    psk.psk_info.identity = coap_bin_const_t {
                        length: identity.len(),
                        s: identity.as_ptr(),
                    };
                    psk.psk_info.key = coap_bin_const_t {
                        length: key.len(),
                        s: key.as_ptr(),
                    };
                    if conf.is_null() {
                        coap_new_client_session_psk2(context, ptr::null(), address.as_raw_address(), proto, &mut psk)
                    } else {
                        coap_new_client_session_oscore_psk(
                            context,
                            ptr::null(),
                            address.as_raw_address(),
                            proto,
                            &mut psk,
                            conf,
                        )
                    }
                },
                Security::Certificate { chain, key, sni } => {
                    if chain.len() > 1024 * 1024 || key.len() > 65536 {
                        if !conf.is_null() {
                            coap_delete_oscore_conf(conf);
                        }
                        return Err("invalid certificate bounds");
                    }
                    let sni = CString::new(sni.as_str()).map_err(|_| "invalid SNI")?;
                    let mut pki: coap_dtls_pki_t = std::mem::zeroed();
                    pki.version = COAP_DTLS_PKI_SETUP_VERSION as u8;
                    pki.verify_peer_cert = 1;
                    pki.client_sni = sni.as_ptr().cast_mut();
                    pki.pki_key.key_type = coap_pki_key_t_COAP_PKI_KEY_PEM_BUF;
                    pki.pki_key.key.pem_buf = coap_pki_key_pem_buf_t {
                        ca_cert: ptr::null(),
                        ca_cert_len: 0,
                        public_cert: if chain.is_empty() { ptr::null() } else { chain.as_ptr() },
                        public_cert_len: chain.len(),
                        private_key: if key.is_empty() { ptr::null() } else { key.as_ptr() },
                        private_key_len: key.len(),
                    };
                    if conf.is_null() {
                        coap_new_client_session_pki(context, ptr::null(), address.as_raw_address(), proto, &mut pki)
                    } else {
                        coap_new_client_session_oscore_pki(
                            context,
                            ptr::null(),
                            address.as_raw_address(),
                            proto,
                            &mut pki,
                            conf,
                        )
                    }
                },
            };
            if client.session.is_null() {
                return Err("session creation failed");
            }
            if let Some(oscore) = oscore {
                for (id, seq, window, initial) in oscore.replay {
                    if coap_context_restore_runtime_replay(context, id.as_ptr(), id.len(), seq, window, initial) != 1 {
                        return Err("OSCORE replay restore failed");
                    }
                }
            }
            // Keep the native transmit MTU. The receive allocation bound is not
            // an instruction to send maximum-sized UDP datagrams.
            coap_session_set_max_retransmit(client.session, limits.maximum_retransmit);
            coap_session_set_ack_timeout(
                client.session,
                coap_fixed_point_t {
                    integer_part: (limits.ack_timeout_ms / 1000) as u16,
                    fractional_part: (limits.ack_timeout_ms % 1000) as u16,
                },
            );
            client.check()?;
            Ok(client)
        }
    }

    pub fn ready(&self) -> bool {
        !self.state.failed
            && unsafe { coap_session_get_state(self.session) == coap_session_state_t_COAP_SESSION_STATE_ESTABLISHED }
    }

    pub fn check(&self) -> Result<(), &'static str> {
        if self.state.failed {
            Err("controlled client stopped")
        } else {
            Ok(())
        }
    }

    pub fn poll(&mut self) -> Result<(), &'static str> {
        self.check()?;
        unsafe {
            if coap_io_process(self.context, u32::MAX) < 0 {
                self.state.failed = true;
            }
        }
        self.check()
    }

    /// Prepare an external event-loop wait, processing any due native timers.
    ///
    /// `None` means no native timer requires a wake. Otherwise the caller must
    /// poll again within the returned duration, or sooner when supplied I/O,
    /// commands or cancellation become ready. This uses libcoap's event-loop
    /// interface, including its retransmission, DTLS and block-transfer timers.
    pub fn prepare_wait(&mut self) -> Result<Option<std::time::Duration>, &'static str> {
        self.check()?;
        let milliseconds = unsafe {
            let mut now = 0;
            coap_ticks(&mut now);
            if coap_epoll_is_supported() != 0 {
                coap_io_prepare_epoll(self.context, now)
            } else {
                let mut count = 0;
                coap_io_prepare_io(self.context, ptr::null_mut(), 0, &mut count, now)
            }
        };
        self.check()?;
        Ok((milliseconds != 0).then_some(std::time::Duration::from_millis(u64::from(milliseconds))))
    }

    pub fn request(
        &mut self,
        token: &[u8],
        code: u8,
        confirmable: bool,
        options: &[(u16, Vec<u8>)],
        payload: Vec<u8>,
    ) -> Result<i32, &'static str> {
        self.check()?;
        if token.is_empty() || token.len() > 8 || !(1..=7).contains(&code) || payload.len() > self.maximum_body {
            return Err("request limits exceeded");
        }
        if options.windows(2).any(|w| w[0].0 > w[1].0)
            || options.iter().map(|o| o.1.len() + 5).sum::<usize>() > self.state.maximum_pdu
        {
            return Err("option limits exceeded");
        }
        unsafe {
            coap_session_set_runtime_peer(self.session, CoapAddress::from(self.peer).as_raw_address());
            let pdu = coap_pdu_init(
                if confirmable {
                    coap_pdu_type_t_COAP_MESSAGE_CON
                } else {
                    coap_pdu_type_t_COAP_MESSAGE_NON
                },
                code.into(),
                i32::from(coap_new_message_id(self.session)),
                self.state.maximum_pdu,
            );
            if pdu.is_null() {
                return Err("request allocation failed");
            }
            if coap_add_token(pdu, token.len(), token.as_ptr()) != 1 {
                coap_delete_pdu(pdu);
                return Err("token rejected");
            }
            for (number, value) in options {
                if coap_add_option(pdu, *number, value.len(), value.as_ptr()) == 0 {
                    coap_delete_pdu(pdu);
                    return Err("option rejected");
                }
            }
            let body = Box::new(Zeroizing::new(payload));
            let length = body.len();
            let pointer = body.as_ptr();
            let body = Box::into_raw(body);
            if coap_add_data_large_request(self.session, pdu, length, pointer, Some(release), body.cast()) != 1 {
                // Native API invokes release on both the failure and success paths.
                coap_delete_pdu(pdu);
                return Err("body rejected");
            }
            let mid = coap_send(self.session, pdu);
            self.check()?;
            if mid < 0 {
                Err("request send failed")
            } else {
                Ok(mid)
            }
        }
    }

    pub fn forget(&mut self, token: &[u8]) -> Result<(), &'static str> {
        self.check()?;
        unsafe {
            if coap_session_forget_runtime_token(self.session, token.as_ptr(), token.len()) != 1 {
                return Err("request cancellation failed");
            }
        }
        Ok(())
    }

    pub fn cancel_observe(&mut self, token: &[u8]) -> Result<(), &'static str> {
        self.check()?;
        let mut token = token.to_vec();
        unsafe {
            let mut binary = coap_binary_t {
                length: token.len(),
                s: token.as_mut_ptr(),
            };
            if coap_cancel_observe(self.session, &mut binary, coap_pdu_type_t_COAP_MESSAGE_CON) == 0 {
                return Err("observation not active");
            }
        }
        self.check()
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            coap_register_response_handler(self.context, None);
            coap_register_nack_handler(self.context, None);
            coap_register_event_handler(self.context, None);
            self.state.failed = true;
            if !self.session.is_null() {
                coap_session_release(self.session);
            }
            coap_free_context(self.context);
        }
    }
}
fn guarded<T: Copy>(data: *mut c_void, fallback: T, action: impl FnOnce(&mut State) -> T) -> T {
    // Callback data points into the pinned Box<State>, freed only after context.
    let state = unsafe { &mut *data.cast::<State>() };
    if state.failed {
        return fallback;
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(state))) {
        Ok(value) => value,
        Err(_) => {
            state.failed = true;
            fallback
        },
    }
}
unsafe extern "C" fn read(data: *mut c_void, buffer: *mut u8, length: usize, peer: *mut coap_address_t) -> isize {
    guarded(data, -1, |s| {
        match s
            .callbacks
            .read(unsafe { std::slice::from_raw_parts_mut(buffer, length) })
        {
            Ok((n, address)) if n <= length => {
                if let Some(address) = address {
                    if !peer.is_null() {
                        unsafe {
                            *peer = CoapAddress::from(address).into_raw_address();
                        }
                    }
                }
                n as isize
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            _ => {
                s.failed = true;
                -1
            },
        }
    })
}
unsafe extern "C" fn write(data: *mut c_void, buffer: *const u8, length: usize, peer: *const coap_address_t) -> isize {
    guarded(data, -1, |s| {
        let address = if peer.is_null() {
            None
        } else {
            Some(
                CoapAddress::from(unsafe { &*peer })
                    .to_socket_addrs()
                    .unwrap()
                    .next()
                    .unwrap(),
            )
        };
        match s
            .callbacks
            .write(unsafe { std::slice::from_raw_parts(buffer, length) }, address)
        {
            Ok(n) if n <= length => n as isize,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            _ => {
                s.failed = true;
                -1
            },
        }
    })
}
unsafe fn data(session: *mut coap_session_t) -> *mut c_void {
    coap_get_app_data(coap_session_get_context(session))
}
unsafe extern "C" fn response(
    session: *mut coap_session_t,
    _sent: *const coap_pdu_t,
    pdu: *const coap_pdu_t,
    mid: coap_mid_t,
) -> coap_response_t {
    guarded(data(session), coap_response_t_COAP_RESPONSE_FAIL, |s| unsafe {
        let token = coap_pdu_get_token(pdu);
        if token.length > 8 {
            s.failed = true;
            return coap_response_t_COAP_RESPONSE_FAIL;
        }
        let mut iterator: coap_opt_iterator_t = std::mem::zeroed();
        coap_option_iterator_init(pdu, &mut iterator, ptr::null());
        let mut options = Vec::new();
        let mut bytes = 0usize;
        loop {
            let option = coap_option_next(&mut iterator);
            if option.is_null() {
                break;
            }
            let length = coap_opt_length(option) as usize;
            bytes = bytes.saturating_add(length);
            if options.len() >= s.maximum_options || bytes > s.maximum_pdu {
                s.failed = true;
                return coap_response_t_COAP_RESPONSE_FAIL;
            }
            options.push((
                iterator.number,
                std::slice::from_raw_parts(coap_opt_value(option), length).to_vec(),
            ));
        }
        let (mut length, mut offset, mut total) = (0, 0, 0);
        let mut body = ptr::null();
        coap_get_data_large(pdu, &mut length, &mut body, &mut offset, &mut total);
        if length > s.maximum_pdu {
            s.failed = true;
            return coap_response_t_COAP_RESPONSE_FAIL;
        }
        let mut block: coap_block_b_t = std::mem::zeroed();
        let more = coap_get_block_b(session, pdu, COAP_OPTION_BLOCK2 as u16, &mut block) != 0 && block.m() != 0;
        let value = Event::Response {
            token: if token.length == 0 {
                vec![]
            } else {
                std::slice::from_raw_parts(token.s, token.length).to_vec()
            },
            code: coap_pdu_get_code(pdu) as u8,
            message_type: coap_pdu_get_type(pdu) as u8,
            mid,
            options,
            payload: if length == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(body, length).to_vec()
            },
            offset,
            total,
            more,
            peer: CoapAddress::from(&*coap_session_get_addr_remote(session))
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
        };
        match s.callbacks.response(value) {
            ResponseDecision::Accept => coap_response_t_COAP_RESPONSE_OK,
            ResponseDecision::Reject => coap_response_t_COAP_RESPONSE_FAIL,
            ResponseDecision::Stop => {
                s.failed = true;
                coap_response_t_COAP_RESPONSE_FAIL
            },
        }
    })
}
unsafe extern "C" fn nack(
    session: *mut coap_session_t,
    pdu: *const coap_pdu_t,
    reason: coap_nack_reason_t,
    mid: coap_mid_t,
) {
    guarded(data(session), (), |s| {
        let token = if pdu.is_null() {
            coap_bin_const_t {
                length: 0,
                s: ptr::null(),
            }
        } else {
            unsafe { coap_pdu_get_token(pdu) }
        };
        if token.length > 8 {
            s.failed = true;
            return;
        }
        #[allow(
            clippy::unnecessary_cast,
            reason = "bindgen emits signed C enums on MSVC and unsigned C enums elsewhere; preserve the raw bits"
        )]
        let value = Event::Nack {
            token: if token.length == 0 {
                vec![]
            } else {
                unsafe { std::slice::from_raw_parts(token.s, token.length) }.to_vec()
            },
            reason: reason as u32,
            mid,
        };
        if !s.callbacks.event(value) {
            s.failed = true;
        }
    });
}
#[allow(
    clippy::unnecessary_cast,
    reason = "bindgen emits signed C enums on MSVC and unsigned C enums elsewhere; preserve the raw bits"
)]
unsafe extern "C" fn event(session: *mut coap_session_t, code: coap_event_t) -> i32 {
    guarded(data(session), 0, |s| {
        if !s.callbacks.event(Event::Session { code: code as u32 }) {
            s.failed = true;
        }
        0
    })
}
unsafe extern "C" fn release(_session: *mut coap_session_t, data: *mut c_void) {
    drop(Box::from_raw(data.cast::<Zeroizing<Vec<u8>>>()));
}
unsafe extern "C" fn reserve(next: u64, data: *mut c_void) -> i32 {
    guarded(data, 0, |s| {
        let ok = s.callbacks.reserve_sender(next);
        s.failed |= !ok;
        i32::from(ok)
    })
}
unsafe extern "C" fn replay(
    data: *mut c_void,
    id: *const u8,
    length: usize,
    seq: u64,
    window: u64,
    initial: u8,
) -> i32 {
    guarded(data, 0, |s| {
        if length > 7 {
            s.failed = true;
            return 0;
        }
        let ok = s.callbacks.save_replay(
            if length == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(id, length) }
            },
            seq,
            window,
            initial,
        );
        s.failed |= !ok;
        i32::from(ok)
    })
}
unsafe extern "C" fn verify(data: *mut c_void, certs: *const *const u8, lengths: *const usize, count: usize) -> i32 {
    guarded(data, 0, |s| {
        if count == 0 || count > 16 {
            return 0;
        }
        let certs = unsafe { std::slice::from_raw_parts(certs, count) };
        let lengths = unsafe { std::slice::from_raw_parts(lengths, count) };
        if lengths.iter().any(|n| *n > 65536) {
            return 0;
        }
        let chain = certs
            .iter()
            .zip(lengths)
            .map(|(p, n)| unsafe { std::slice::from_raw_parts(*p, *n) })
            .collect::<Vec<_>>();
        i32::from(s.callbacks.verify(&chain))
    })
}

/// Encode an unsigned CoAP option using the native library.
pub fn encode_uint(value: u64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let length = unsafe { coap_encode_var_safe8(bytes.as_mut_ptr(), bytes.len(), value) };
    bytes[..length as usize].to_vec()
}

#[cfg(test)]
mod controlled_io_tests {
    use super::*;
    struct Idle;
    impl Callbacks for Idle {
        fn read(&mut self, _: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn write(&mut self, bytes: &[u8], _: Option<SocketAddr>) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn event(&mut self, _: Event) -> bool {
            true
        }
    }
    fn oscore_configuration(recipients: u8, salt_bytes: usize) -> Vec<u8> {
        let mut configuration = format!(
            "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\nsender_id,hex,\"00\"\nmaster_salt,hex,\"{}\"\n",
            "ab".repeat(salt_bytes)
        );
        for id in 1..=recipients {
            configuration.push_str(&format!("recipient_id,hex,\"{id:02x}\"\n"));
        }
        configuration.into_bytes()
    }
    fn oscore_client(oscore: Oscore) -> Result<Client, &'static str> {
        Client::new(
            "127.0.0.1:5683".parse().unwrap(),
            false,
            Security::None,
            Some(oscore),
            Limits {
                maximum_pdu: 1024,
                maximum_body: 4096,
                maximum_options: 128,
                maximum_retransmit: 4,
                ack_timeout_ms: 2000,
            },
            Box::new(Idle),
        )
    }
    #[test]
    fn oscore_configuration_reaches_the_native_parser_without_a_byte_quota() {
        let configuration = oscore_configuration(1, 2048);
        assert!(configuration.len() > 4096);
        ensure_coap_started();
        unsafe {
            let conf = coap_new_oscore_conf(
                coap_str_const_t {
                    length: configuration.len(),
                    s: configuration.as_ptr(),
                },
                None,
                ptr::null_mut(),
                0,
            );
            assert!(!conf.is_null(), "the native parser accepts the complete configuration");
            coap_delete_oscore_conf(conf);
        }
        let client = oscore_client(Oscore {
            configuration: configuration.into(),
            sender_next: (1u64 << 40) - 1,
            replay: vec![],
        })
        .unwrap();
        assert!(
            client.ready(),
            "native OSCORE key derivation and session creation succeed"
        );
        // The sender sequence's actual OSCORE capacity still governs admission.
        assert_eq!(
            oscore_client(Oscore {
                configuration: oscore_configuration(1, 0).into(),
                sender_next: 1u64 << 40,
                replay: vec![],
            })
            .err(),
            Some("invalid OSCORE configuration bound")
        );
    }
    #[test]
    fn oscore_restores_all_configured_native_recipients() {
        let replay = (1..=17).map(|id| (vec![id], u64::from(id), 3, 0)).collect();
        let client = oscore_client(Oscore {
            configuration: oscore_configuration(17, 0).into(),
            sender_next: 0,
            replay,
        })
        .unwrap();
        assert!(client.ready());
        // Each restore must match a native recipient, including the final one;
        // an unconfigured recipient is still refused by the native restore API.
        assert_eq!(
            oscore_client(Oscore {
                configuration: oscore_configuration(16, 0).into(),
                sender_next: 0,
                replay: (1..=17).map(|id| (vec![id], u64::from(id), 3, 0)).collect(),
            })
            .err(),
            Some("OSCORE replay restore failed")
        );
    }
    #[test]
    fn representable_retransmission_parameters_reach_the_native_session() {
        for (maximum_retransmit, ack_timeout_ms) in [(9, 1000), (1, 477_218)] {
            let client = Client::new(
                "127.0.0.1:5683".parse().unwrap(),
                false,
                Security::None,
                None,
                Limits {
                    maximum_pdu: 1024,
                    maximum_body: 4096,
                    maximum_options: 128,
                    maximum_retransmit,
                    ack_timeout_ms,
                },
                Box::new(Idle),
            )
            .unwrap();
            unsafe {
                assert_eq!(coap_session_get_max_retransmit(client.session), maximum_retransmit);
                let ack = coap_session_get_ack_timeout(client.session);
                assert_eq!(
                    u32::from(ack.integer_part) * 1000 + u32::from(ack.fractional_part),
                    ack_timeout_ms
                );
            }
        }
    }
    #[test]
    fn native_retransmission_arithmetic_fits_at_each_joint_boundary() {
        // Exercise the real native randomized calculation, not another engine.
        unsafe extern "C" {
            fn coap_calc_timeout(session: *mut coap_session_t, random: u8) -> std::ffi::c_uint;
        }
        for (maximum_retransmit, expected) in [
            (1, 477_218),
            (2, 204_522),
            (3, 95_443),
            (4, 46_182),
            (5, 22_724),
            (6, 11_272),
            (7, 5_614),
            (8, 2_801),
            (9, 1_399),
        ] {
            let ack_timeout_ms = retransmit_ack_timeout_maximum_ms(maximum_retransmit);
            assert_eq!(ack_timeout_ms, expected);
            let limits = |ack_timeout_ms| Limits {
                maximum_pdu: 1024,
                maximum_body: 4096,
                maximum_options: 128,
                maximum_retransmit,
                ack_timeout_ms,
            };
            let client = Client::new(
                "127.0.0.1:5683".parse().unwrap(),
                false,
                Security::None,
                None,
                limits(ack_timeout_ms),
                Box::new(Idle),
            )
            .unwrap();
            for random in 0..=255 {
                let ticks = unsafe { coap_calc_timeout(client.session, random) };
                assert!(ticks >= 1000);
                let shifted = ticks.checked_mul(1 << maximum_retransmit).unwrap();
                shifted.checked_mul(1000).unwrap();
            }
            assert!(Client::new(
                "127.0.0.1:5683".parse().unwrap(),
                false,
                Security::None,
                None,
                limits(ack_timeout_ms + 1),
                Box::new(Idle),
            )
            .is_err());
        }
        assert_eq!(retransmit_ack_timeout_maximum_ms(10), 699);
        for maximum in [30, 31, 255, 256, u16::MAX] {
            assert_eq!(retransmit_ack_timeout_maximum_ms(maximum), 0);
        }
    }
    /// A peer the test answers by hand: written packets and events are kept.
    #[derive(Default)]
    struct Wire {
        inbox: std::collections::VecDeque<Vec<u8>>,
        written: Vec<Vec<u8>>,
        events: Vec<Event>,
    }
    struct Scripted(Rc<std::cell::RefCell<Wire>>);
    impl Callbacks for Scripted {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            let packet = self.0.borrow_mut().inbox.pop_front().ok_or(io::ErrorKind::WouldBlock)?;
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), Some("127.0.0.1:5683".parse().unwrap())))
        }

        fn write(&mut self, bytes: &[u8], _: Option<SocketAddr>) -> io::Result<usize> {
            self.0.borrow_mut().written.push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn event(&mut self, event: Event) -> bool {
            self.0.borrow_mut().events.push(event);
            true
        }
    }
    /// A piggybacked 2.05 answering `request` with `options` and `payload`.
    fn answer(request: &[u8], options: &[u8], payload: &[u8]) -> Vec<u8> {
        let token = usize::from(request[0] & 15);
        let mut message = vec![0x60 | token as u8, 69, request[2], request[3]];
        message.extend_from_slice(&request[4..4 + token]);
        message.extend_from_slice(options);
        message.push(0xff);
        message.extend_from_slice(payload);
        message
    }
    fn scripted_client() -> (Rc<std::cell::RefCell<Wire>>, Client) {
        let wire = Rc::new(std::cell::RefCell::new(Wire::default()));
        let client = Client::new(
            "127.0.0.1:5683".parse().unwrap(),
            false,
            Security::None,
            None,
            Limits {
                maximum_pdu: 1024,
                maximum_body: 4096,
                maximum_options: 128,
                maximum_retransmit: 4,
                ack_timeout_ms: 2000,
            },
            Box::new(Scripted(wire.clone())),
        )
        .unwrap();
        (wire, client)
    }
    #[test]
    fn reliable_client_keeps_the_native_csm_timer_and_accepts_peer_csm() {
        ensure_coap_started();
        let native_timeout_ms = unsafe {
            let context = coap_new_context(ptr::null());
            assert!(!context.is_null());
            let timeout = coap_context_get_csm_timeout_ms(context);
            coap_free_context(context);
            timeout
        };
        let wire = Rc::new(std::cell::RefCell::new(Wire::default()));
        let mut client = Client::new(
            "127.0.0.1:5683".parse().unwrap(),
            true,
            Security::None,
            None,
            Limits {
                maximum_pdu: 1024,
                maximum_body: 4096,
                maximum_options: 128,
                maximum_retransmit: 4,
                ack_timeout_ms: 2000,
            },
            Box::new(Scripted(wire.clone())),
        )
        .unwrap();
        assert_eq!(
            unsafe { coap_context_get_csm_timeout_ms(client.context) },
            native_timeout_ms,
            "the controlled client must inherit the native context's CSM behavior"
        );
        assert!(!client.ready());
        assert!(wire.borrow().written.iter().any(|packet| packet.get(1) == Some(&0xe1)));
        let wait = client.prepare_wait().unwrap().expect("the native CSM timer is pending");
        assert!(wait <= std::time::Duration::from_millis(u64::from(native_timeout_ms)));
        // Independently encoded RFC 8323 CSM: no token, options or payload.
        wire.borrow_mut().inbox.push_back(vec![0x00, 0xe1]);
        client.poll().unwrap();
        assert!(client.ready(), "the peer's CSM establishes the reliable session");
    }
    #[test]
    fn external_wait_preserves_a_silent_peers_retransmission() {
        let (wire, mut client) = scripted_client();
        let token = [0x71];
        client.request(&token, 1, true, &[], Vec::new()).unwrap();
        assert_eq!(wire.borrow().written.len(), 1);
        let wait = client
            .prepare_wait()
            .unwrap()
            .expect("a CON has a retransmission timer");
        assert!(wait <= std::time::Duration::from_secs(3));
        // Wall clock: libcoap's own retransmission timer is the subject. No
        // input or repeated poll drives it before the returned native wait.
        std::thread::sleep(wait + std::time::Duration::from_millis(1));
        client.poll().unwrap();
        {
            let wire = wire.borrow();
            assert_eq!(wire.written.len(), 2);
            assert_eq!(wire.written[0], wire.written[1]);
        }
        client.forget(&token).unwrap();
    }
    #[allow(
        clippy::unnecessary_cast,
        reason = "bindgen emits signed C enums on MSVC and unsigned C enums elsewhere; preserve the raw bits"
    )]
    fn body_incomplete(events: &[Event], expected: &[u8]) -> bool {
        events.iter().any(|event| {
            matches!(
                event,
                Event::Nack { token, reason, .. }
                    if token == expected && *reason == coap_nack_reason_t_COAP_NACK_BODY_INCOMPLETE as u32
            )
        })
    }
    #[test]
    fn a_streamed_body_that_cannot_complete_fails_its_own_request_without_another() {
        // ETag 7, Block2 0/M/16, Size2 32.
        let first = [0x41, 7, 0xd1, 6, 0x08, 0x51, 32];
        for (case, second) in [
            // The representation changed: ETag 8.
            ("etag", vec![0x41, 8, 0xd1, 6, 0x10, 0x51, 32]),
            // Content-Format 50 where the first block had none.
            ("content-format", vec![0x41, 7, 0x81, 50, 0xb1, 0x10, 0x51, 32]),
            // The first block had an ETag; this one has none.
            ("missing etag", vec![0xd1, 10, 0x10, 0x51, 32]),
        ] {
            let (wire, mut client) = scripted_client();
            client
                .request(&[1], 2, true, &[(11, b"report".to_vec())], b"body".to_vec())
                .unwrap();
            client.poll().unwrap();
            let request = wire.borrow().written.last().unwrap().clone();
            assert_eq!(request[1], 2, "{case}: the declared POST");
            wire.borrow_mut().inbox.push_back(answer(&request, &first, &[b'a'; 16]));
            client.poll().unwrap();
            let next = wire.borrow().written.last().unwrap().clone();
            assert_ne!(next, request, "{case}: the second block is requested");
            wire.borrow_mut().inbox.push_back(answer(&next, &second, &[b'b'; 16]));
            client.poll().unwrap();
            client.poll().unwrap();
            let wire = wire.borrow();
            let requests = wire.written.iter().filter(|packet| packet[1] != 0).count();
            assert_eq!(requests, 2, "{case}: nothing is requested again");
            let responses = wire
                .events
                .iter()
                .filter(|e| matches!(e, Event::Response { .. }))
                .count();
            assert_eq!(responses, 1, "{case}: only the first block is delivered");
            assert!(body_incomplete(&wire.events, &[1]), "{case}: {:?}", wire.events);
        }
    }
    #[test]
    fn a_body_whose_blocks_outrun_tracking_fails_its_own_request_without_another() {
        let (wire, mut client) = scripted_client();
        client
            .request(&[1], 1, true, &[(11, b"large".to_vec())], vec![])
            .unwrap();
        client.poll().unwrap();
        // Each answer skips the block asked for, so every block opens a new
        // received range: libcoap tracks three, and the fourth answer overflows.
        for number in [0u8, 2, 4, 6] {
            let request = wire.borrow().written.last().unwrap().clone();
            // ETag 7, Block2 number/M/16, Size2 128.
            let options = [0x41, 7, 0xd1, 6, (number << 4) | 8, 0x51, 128];
            wire.borrow_mut()
                .inbox
                .push_back(answer(&request, &options, &[number; 16]));
            client.poll().unwrap();
        }
        client.poll().unwrap();
        let wire = wire.borrow();
        let requests = wire.written.iter().filter(|packet| packet[1] != 0).count();
        assert_eq!(requests, 4, "the request and one continuation per tracked block");
        let responses = wire
            .events
            .iter()
            .filter(|e| matches!(e, Event::Response { .. }))
            .count();
        assert_eq!(responses, 3, "the overflowing block is not delivered");
        assert!(body_incomplete(&wire.events, &[1]), "{:?}", wire.events);
    }
    #[test]
    fn outgoing_options_are_not_limited_by_the_receive_option_count() {
        let (wire, mut client) = scripted_client();
        let options = vec![(2048, Vec::new()); 129];
        client.request(&[1], 1, false, &options, Vec::new()).unwrap();
        let wire = wire.borrow();
        assert_eq!(wire.written.len(), 1);
        let packet = &wire.written[0];
        let mut rest = &packet[4 + usize::from(packet[0] & 15)..];
        let mut number = 0;
        let mut received = Vec::new();
        fn extended(nibble: u8, rest: &mut &[u8]) -> u16 {
            match nibble {
                0..=12 => u16::from(nibble),
                13 => {
                    let n = 13 + u16::from(rest[0]);
                    *rest = &rest[1..];
                    n
                },
                14 => {
                    let n = 269 + u16::from_be_bytes([rest[0], rest[1]]);
                    *rest = &rest[2..];
                    n
                },
                _ => panic!("invalid option encoding"),
            }
        }
        // Decode RFC 7252 options independently. libcoap may also add its own
        // Request-Tag; all 129 caller options must follow it without loss.
        while !rest.is_empty() {
            let header = rest[0];
            rest = &rest[1..];
            number += extended(header >> 4, &mut rest);
            let length = usize::from(extended(header & 15, &mut rest));
            let value = rest[..length].to_vec();
            rest = &rest[length..];
            if number == 2048 {
                received.push((number, value));
            }
        }
        assert_eq!(received, options);
    }

    #[test]
    fn psk_native_capacity_reaches_the_peer_without_truncation() {
        use std::net::UdpSocket;

        use crate::crypto::psk::{PskKey, ServerPskContextBuilder};
        struct Datagram(UdpSocket);
        impl Callbacks for Datagram {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
                self.0.recv_from(buffer).map(|(n, peer)| (n, Some(peer)))
            }

            fn write(&mut self, bytes: &[u8], peer: Option<SocketAddr>) -> io::Result<usize> {
                self.0.send_to(bytes, peer.unwrap())
            }

            fn event(&mut self, _: Event) -> bool {
                true
            }
        }
        for (identity_len, key_len) in [(129, 65), (PSK_IDENTITY_MAXIMUM_BYTES, PSK_KEY_MAXIMUM_BYTES)] {
            let identity = vec![b'i'; identity_len];
            let mut key = vec![0x5a; key_len];
            key[key_len - 1] = 0xa7;
            let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
            let peer = reservation.local_addr().unwrap();
            drop(reservation);
            let mut server = crate::CoapContext::new().unwrap();
            // Only an exact identity selects the complete expected key. A
            // successful Finished verifies that the client used every key byte.
            server
                .set_psk_context(
                    ServerPskContextBuilder::new(PskKey::new(Some("wrong"), vec![0; 16]))
                        .id_key_provider(vec![PskKey::new(Some(identity.clone()), key.clone())])
                        .build(),
                )
                .unwrap();
            server.add_endpoint_dtls(peer).unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut client = Client::new(
                peer,
                false,
                Security::Psk {
                    identity: Zeroizing::new(identity),
                    key: Zeroizing::new(key),
                    sni: "localhost".into(),
                },
                None,
                Limits {
                    maximum_pdu: 2048,
                    maximum_body: 4096,
                    maximum_options: 128,
                    maximum_retransmit: 2,
                    ack_timeout_ms: 1000,
                },
                Box::new(Datagram(socket)),
            )
            .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !client.ready() {
                assert!(std::time::Instant::now() < deadline, "DTLS handshake did not complete");
                server.do_io(Some(std::time::Duration::from_millis(1))).unwrap();
                client.poll().unwrap();
            }
        }
    }

    #[test]
    fn psk_excess_names_the_native_capacity_before_native_session_creation() {
        for (identity_len, key_len, expected) in [
            (
                PSK_IDENTITY_MAXIMUM_BYTES + 1,
                1,
                "PSK identity exceeds native PSK_MAX_IDENTITY_LEN minus its NUL terminator",
            ),
            (1, PSK_KEY_MAXIMUM_BYTES + 1, "PSK key exceeds native PSK_MAX_PSK_LEN"),
        ] {
            let result = Client::new(
                "127.0.0.1:5684".parse().unwrap(),
                false,
                Security::Psk {
                    identity: Zeroizing::new(vec![b'i'; identity_len]),
                    key: Zeroizing::new(vec![0xa7; key_len]),
                    sni: "localhost".into(),
                },
                None,
                Limits {
                    maximum_pdu: 1024,
                    maximum_body: 4096,
                    maximum_options: 128,
                    maximum_retransmit: 2,
                    ack_timeout_ms: 1000,
                },
                Box::new(Idle),
            );
            assert_eq!(result.err(), Some(expected));
        }
    }

    #[test]
    fn the_supplied_receive_option_limit_still_protects_the_callback() {
        for count in [129, 130] {
            let wire = Rc::new(std::cell::RefCell::new(Wire::default()));
            let mut client = Client::new(
                "127.0.0.1:5683".parse().unwrap(),
                false,
                Security::None,
                None,
                Limits {
                    maximum_pdu: 1024,
                    maximum_body: 4096,
                    maximum_options: 129,
                    maximum_retransmit: 2,
                    ack_timeout_ms: 1000,
                },
                Box::new(Scripted(wire.clone())),
            )
            .unwrap();
            client.request(&[1], 1, true, &[], Vec::new()).unwrap();
            let request = wire.borrow().written[0].clone();
            let mut options = vec![0xe0, 0x06, 0xf3];
            options.resize(options.len() + count - 1, 0);
            wire.borrow_mut().inbox.push_back(answer(&request, &options, b"ok"));
            let result = client.poll();
            assert_eq!(result.is_ok(), count == 129);
            assert_eq!(
                wire.borrow()
                    .events
                    .iter()
                    .any(|e| matches!(e, Event::Response { options, .. }
                if options.len() == count)),
                count == 129
            );
        }
    }

    #[test]
    fn psk_accepts_short_nonempty_protocol_keys() {
        for key in [
            vec![],
            vec![1],
            b"secretPSK".to_vec(),
            vec![1; 65],
            vec![1; PSK_KEY_MAXIMUM_BYTES + 1],
        ] {
            let valid = !key.is_empty() && key.len() <= PSK_KEY_MAXIMUM_BYTES;
            let result = Client::new(
                "127.0.0.1:5684".parse().unwrap(),
                false,
                Security::Psk {
                    identity: Zeroizing::new(b"fixture".to_vec()),
                    key: Zeroizing::new(key),
                    sni: "localhost".into(),
                },
                None,
                Limits {
                    maximum_pdu: 1024,
                    maximum_body: 4096,
                    maximum_options: 128,
                    maximum_retransmit: 4,
                    ack_timeout_ms: 2000,
                },
                Box::new(Idle),
            );
            assert_eq!(result.is_ok(), valid);
        }
    }
    #[test]
    fn supplied_tcp_pdu_uses_the_runtime_receive_maximum() {
        struct Stream {
            input: std::io::Cursor<Vec<u8>>,
            received: Rc<std::cell::Cell<usize>>,
        }
        impl Callbacks for Stream {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
                use std::io::Read;
                let n = self.input.read(buffer)?;
                if n == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok((n, None))
            }

            fn write(&mut self, bytes: &[u8], _: Option<SocketAddr>) -> io::Result<usize> {
                Ok(bytes.len())
            }

            #[allow(
                clippy::unnecessary_cast,
                reason = "bindgen emits signed C enums on MSVC and unsigned C enums elsewhere; preserve the raw bits"
            )]
            fn event(&mut self, event: Event) -> bool {
                match event {
                    Event::Response { payload, .. } => self.received.set(payload.len()),
                    Event::Session { code }
                        if code == coap_event_t_COAP_EVENT_TCP_CLOSED as u32
                            || code == coap_event_t_COAP_EVENT_TCP_FAILED as u32
                            || code == coap_event_t_COAP_EVENT_SESSION_FAILED as u32 =>
                    {
                        return false
                    },
                    _ => {},
                }
                true
            }
        }
        let maximum = 9 * 1024 * 1024;
        for payload_size in [8 * 1024 * 1024 + 512, maximum + 1] {
            // RFC 8323: CSM, then a 2.05 with token 1 and a payload. The
            // length field excludes its header, code and token.
            let mut input = vec![0x00, 0xe1];
            input.push(0xf1);
            input.extend_from_slice(&((payload_size + 1 - 65805) as u32).to_be_bytes());
            input.extend_from_slice(&[69, 1, 0xff]);
            input.resize(input.len() + payload_size, 0x5a);
            let received = Rc::new(std::cell::Cell::new(0));
            let mut client = Client::new(
                "127.0.0.1:5683".parse().unwrap(),
                true,
                Security::None,
                None,
                Limits {
                    maximum_pdu: maximum,
                    maximum_body: maximum,
                    maximum_options: 128,
                    maximum_retransmit: 2,
                    ack_timeout_ms: 1000,
                },
                Box::new(Stream {
                    input: std::io::Cursor::new(input),
                    received: received.clone(),
                }),
            )
            .unwrap();
            // Register the exchange before its hand-authored response arrives.
            client.request(&[1], 1, false, &[], Vec::new()).unwrap();
            let mut failed = false;
            for _ in 0..(payload_size / 64 + 1024) {
                if client.poll().is_err() {
                    failed = true;
                    break;
                }
                if received.get() != 0 {
                    break;
                }
            }
            if payload_size < maximum {
                assert!(!failed, "a PDU within the configured maximum must be accepted");
                assert_eq!(received.get(), payload_size);
            } else {
                assert!(failed, "a PDU above the configured maximum must be refused");
                assert_eq!(received.get(), 0);
            }
        }
    }
    #[test]
    fn supplied_io_polls_without_native_socket_descriptors() {
        for tcp in [false, true] {
            let mut client = Client::new(
                "127.0.0.1:5683".parse().unwrap(),
                tcp,
                Security::None,
                None,
                Limits {
                    maximum_pdu: 1024,
                    maximum_body: 4096,
                    maximum_options: 128,
                    maximum_retransmit: 4,
                    ack_timeout_ms: 2000,
                },
                Box::new(Idle),
            )
            .unwrap();
            for _ in 0..3 {
                client.poll().unwrap();
            }
        }
    }
}
