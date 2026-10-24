// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * wrapper.h - wrapper header to generate libcoap Rust bindings using bindgen
 */

#include <coap3/coap.h>

#if __has_include(<coap3/coap_defines.h>)
#include <coap3/coap_defines.h>
#endif

/* runtime-io always builds the bundled OpenSSL backend. Match the buffer
 * capacities passed by OpenSSL to libcoap's PSK client callback; libcoap
 * reserves one identity byte for the terminating NUL (coap_openssl.c).
 */
#ifdef LIBCOAP_RS_RUNTIME_IO
#include <openssl/ssl.h>
#define COAP_RUNTIME_PSK_IDENTITY_MAXIMUM_BYTES (PSK_MAX_IDENTITY_LEN - 1)
#define COAP_RUNTIME_PSK_KEY_MAXIMUM_BYTES PSK_MAX_PSK_LEN
#endif
