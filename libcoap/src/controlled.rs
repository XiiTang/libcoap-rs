// SPDX-License-Identifier: BSD-2-Clause
//! A single-thread-owned client using supplied I/O. The native engine owns all
//! CoAP exchanges, retransmission, Observe, Block1/2, BERT, DTLS and OSCORE.
use crate::{context::ensure_coap_started, types::CoapAddress};
use libcoap_sys::*;
use std::{
    ffi::{c_void, CString},
    io,
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    ptr,
    rc::Rc,
};
use zeroize::Zeroizing;

/// Callbacks run synchronously on the client's owner thread. They must not
/// re-enter the client. A false event/persistence result permanently stops it.
pub trait Callbacks {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)>;
    fn write(&mut self, bytes: &[u8], peer: Option<SocketAddr>) -> io::Result<usize>;
    fn event(&mut self, event: Event) -> bool;
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
    pub maximum_options: usize,
    pub maximum_retransmit: u16,
    pub ack_timeout_ms: u32,
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
        if !(64..=16 * 1024 * 1024).contains(&limits.maximum_pdu)
            || limits.maximum_body == 0
            || limits.maximum_options > 128
            || limits.maximum_retransmit > 8
            || !(100..=60000).contains(&limits.ack_timeout_ms)
        {
            return Err("invalid client limits");
        }
        if tcp && !matches!(security, Security::None) {
            return Err("supply already verified TLS over the TCP transport");
        }
        match &security {
            Security::Psk { sni, .. } | Security::Certificate { sni, .. } if sni.as_bytes().contains(&0) => {
                return Err("invalid SNI")
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
            coap_context_set_csm_timeout_ms(context, 5000);
            coap_register_response_handler(context, Some(response));
            coap_register_nack_handler(context, Some(nack));
            coap_register_event_handler(context, Some(event));
            coap_context_set_runtime_verify(context, Some(verify));
            let mut conf = ptr::null_mut();
            if let Some(oscore) = &oscore {
                if oscore.configuration.len() > 4096 || oscore.sender_next >= (1u64 << 40) || oscore.replay.len() > 16 {
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
                    if identity.is_empty() || identity.len() > 128 || key.is_empty() || key.len() > 64 {
                        if !conf.is_null() {
                            coap_delete_oscore_conf(conf);
                        }
                        return Err("invalid PSK bounds");
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
    pub fn request(
        &mut self,
        token: &[u8],
        code: u8,
        confirmable: bool,
        options: &[(u16, Vec<u8>)],
        payload: Vec<u8>,
    ) -> Result<i32, &'static str> {
        self.check()?;
        if token.is_empty()
            || token.len() > 8
            || !(1..=7).contains(&code)
            || options.len() > self.state.maximum_options
            || payload.len() > self.maximum_body
        {
            return Err("request limits exceeded");
        }
        if options.windows(2).any(|w| w[0].0 > w[1].0)
            || options.iter().map(|o| o.1.len() + 5).sum::<usize>() > self.state.maximum_pdu / 2
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
        if !s.callbacks.event(value) {
            s.failed = true;
            coap_response_t_COAP_RESPONSE_FAIL
        } else {
            coap_response_t_COAP_RESPONSE_OK
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
        fn event(&mut self, _: Event) -> bool { true }
    }
    #[test]
    fn psk_accepts_short_nonempty_protocol_keys() {
        for key in [vec![], b"secretPSK".to_vec(), vec![1;65]] {
            let valid = !key.is_empty() && key.len() <= 64;
            let result = Client::new("127.0.0.1:5684".parse().unwrap(), false,
                Security::Psk { identity: b"fixture".to_vec(), key, sni: "localhost".into() },
                None, Limits { maximum_pdu: 1024, maximum_body: 4096,
                    maximum_options: 128, maximum_retransmit: 4, ack_timeout_ms: 2000 }, Box::new(Idle));
            assert_eq!(result.is_ok(), valid);
        }
    }
    #[test]
    fn supplied_io_polls_without_native_socket_descriptors() {
        for tcp in [false, true] {
            let mut client = Client::new("127.0.0.1:5683".parse().unwrap(), tcp,
                Security::None, None, Limits { maximum_pdu: 1024, maximum_body: 4096,
                    maximum_options: 128, maximum_retransmit: 4, ack_timeout_ms: 2000 },
                Box::new(Idle)).unwrap();
            for _ in 0..3 { client.poll().unwrap(); }
        }
    }
}
