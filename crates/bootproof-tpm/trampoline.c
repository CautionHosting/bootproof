/* TCTI transmit/receive trampoline: dialect shim + optional hex logging.
 *
 * Always installed by bootproof-tpm (esys.rs):
 * - Dialect fix: the StageX/NitroTPM firmware rejects TPM2_StartAuthSession
 *   (CC 0x0176) commands that carry a non-zero sessionAttributes byte in
 *   the NULL-symmetric case (its esys stack emits 0x01, the working
 *   tpm2-tools traffic shows 0x00). The byte sits at offset 54 in a 59-byte
 *   command (after tpmKey/bind/nonceCaller/encSalt). Zero it before
 *   forwarding. Standard firmware already sends/accepts 0x00 there, so the
 *   rewrite is a no-op for spec-conformant TPMs with NULL symmetric.
 * - Hex logging (opt-in via bp_set_log, driven by BP_LOG_TCTI=1): dump
 *   every outgoing command and incoming response to stderr.
 *
 * Built by build.rs with clang -c; linked into the esys binaries. */

#include <stdio.h>
#include <string.h>

typedef unsigned int (*bp_tx_fn)(void *, unsigned long, const unsigned char *);
typedef unsigned int (*bp_rx_fn)(void *, unsigned long *,
                                 unsigned char *, int);
static bp_tx_fn bp_orig_tx = 0;
static bp_rx_fn bp_orig_rx = 0;
static int bp_log = 0;

void bp_tx_set_orig(void *fn) { bp_orig_tx = (bp_tx_fn)fn; }
void bp_rx_set_orig(void *fn) { bp_orig_rx = (bp_rx_fn)fn; }
void bp_set_log(int v) { bp_log = v; }

static void bp_hex(const char *tag, const unsigned char *p, unsigned long n) {
    static const char hexd[] = "0123456789abcdef";
    unsigned long i;
    if (n > 8192) n = 8192;
    for (i = 0; i < n; i++) {
        fputc(hexd[(p[i] >> 4) & 0xF], stderr);
        fputc(hexd[p[i] & 0xF], stderr);
    }
    fputc(' ', stderr);
    fputc(tag[0], stderr);
    fputc('\n', stderr);
    fflush(stderr);
}

unsigned int bp_tx(void *ctx, unsigned long n, const unsigned char *p) {
    static unsigned char fixbuf[8192];
    if (bp_log) bp_hex("W", p, n);
    if (!bp_orig_tx) return 1;
    /* SAS: clear sessionAttributes for the NULL-symmetric case. */
    if (n >= 59 && n <= sizeof(fixbuf) &&
        p[6] == 0 && p[7] == 0 && p[8] == 0x01 && p[9] == 0x76 &&
        p[54] != 0) {
        memcpy(fixbuf, p, n);
        fixbuf[54] = 0;
        return bp_orig_tx(ctx, n, fixbuf);
    }
    return bp_orig_tx(ctx, n, p);
}

unsigned int bp_rx(void *ctx, unsigned long *n, unsigned char *p, int t) {
    unsigned int rc;
    if (!bp_orig_rx) return 1;
    rc = bp_orig_rx(ctx, n, p, t);
    if (bp_log && rc == 0 && n && p) bp_hex("R", p, *n);
    return rc;
}
