#ifndef PIPELINE_PORT_STUB_C99_H
#define PIPELINE_PORT_STUB_C99_H

/*
 * Stand-in for the eventual C99 internal ports (SHA-256, secp256k1 Schnorr,
 * qrcodegen -- see spec #24). Declared here in plain C89-compatible form;
 * only port_stub_c99.c itself requires C99, never its callers.
 */
unsigned char port_stub_marker(void);

#endif /* PIPELINE_PORT_STUB_C99_H */
