// tpmprobe: decode a TPM RC using the DIALECT tss2-rc, and (with -c) run a
// minimal Create of a keyedHash data object against /dev/tpm0 to bisect the
// 0x18a failure. Built in the Containerfile `tpm` stage (has the dialect
// static libs + headers), extracted and run in the guest.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

static TSS2_TCTI_CONTEXT *dev_tcti(const char *path) {
    size_t size = 0;
    TSS2_RC rc = Tss2_Tcti_Device_Init(NULL, &size, path);
    if (rc) { fprintf(stderr, "Tcti_Device_Init(size): 0x%x %s\n", rc, Tss2_RC_Decode(rc)); return NULL; }
    TSS2_TCTI_CONTEXT *ctx = malloc(size);
    if (!ctx) return NULL;
    rc = Tss2_Tcti_Device_Init(ctx, &size, path);
    if (rc) { free(ctx); fprintf(stderr, "Tcti_Device_Init: 0x%x %s\n", rc, Tss2_RC_Decode(rc)); return NULL; }
    return ctx;
}

static void decode(uint32_t rc) {
    TSS2_RC_INFO info;
    if (!Tss2_RC_DecodeInfo(rc, &info)) {
        printf("  Tss2_RC_DecodeInfo(0x%08x) rejected\n", rc);
    } else {
        printf("  layer=%d format=%d error=0x%08x parameter=%d session=%d handle=%d\n",
               info.layer, info.format, info.error, info.parameter, info.session, info.handle);
    }
    printf("  Tss2_RC_Decode(0x%08x) = %s\n", rc, Tss2_RC_Decode(rc));
}

int main(int argc, char **argv) {
    int do_create = 0;
    uint32_t want_attrs = 0x52; // fixedTPM|fixedParent|userWithAuth (dialect bits)
    if (argc >= 2 && strcmp(argv[1], "-c") == 0) {
        do_create = 1;
        if (argc >= 4 && sscanf(argv[3], "%x", &want_attrs) == 1) {}
    }
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '0' && argv[i][1] == 'x' || (argv[i][0] >= '0' && argv[i][0] <= '9' && !do_create)) {
            uint32_t rc = (uint32_t)strtoul(argv[i], NULL, 0);
            printf("== decoding 0x%08x ==\n", rc);
            decode(rc);
        }
    }
    if (!do_create) {
        // defaults of interest
        printf("== decoding 0x0000018a ==\n"); decode(0x18a);
        printf("== decoding 0x00000180 ==\n"); decode(0x180);
        return 0;
    }

    // ---- minimal Create of a keyedHash data object ----
    const char *path = argc >= 3 ? argv[2] : "/dev/tpm0";
    TSS2_TCTI_CONTEXT *tcti = dev_tcti(path);
    if (!tcti) return 1;
    ESYS_CONTEXT *esys = NULL;
    TSS2_RC rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc) { fprintf(stderr, "Esys_Initialize: 0x%x %s\n", rc, Tss2_RC_Decode(rc)); return 1; }

    // storage parent, OWNER hierarchy (ESAPI maps the handle)
    ESYS_TR parent = ESYS_TR_RH_OWNER;
    TPM2B_PUBLIC *pparent = NULL;
    rc = Esys_CreatePrimary(esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE,
                            NULL, NULL, NULL, NULL,
                            &parent, &pparent, NULL, NULL, NULL);
    if (rc) { fprintf(stderr, "CreatePrimary: 0x%x %s\n", rc, Tss2_RC_Decode(rc)); return 1; }
    printf("parent=0x%08x\n", (uint32_t)parent);

    // template: keyedHash exclusiveOr, SHA256 name, attrs as requested
    TPMT_PUBLIC tpl;
    memset(&tpl, 0, sizeof tpl);
    tpl.type = TPM2_ALG_KEYEDHASH;
    tpl.nameAlg = TPM2_ALG_SHA256;
    tpl.objectAttributes = want_attrs;
    // authPolicy empty
    tpl.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_XOR;
    tpl.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM2_ALG_SHA256;
    tpl.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM2_ALG_KDF1_SP800_56A;
    // unique empty (digest size 0)

    TPM2B_DATA outside = { .size = 0 };
    TPML_PCR_SELECTION cpcr; memset(&cpcr, 0, sizeof cpcr);

    // sensitive: 4 bytes of data
    const uint8_t data[4] = { 0xde, 0xad, 0xbe, 0xef };
    TPM2B_SENSITIVE_CREATE sens; memset(&sens, 0, sizeof sens);
    // dialect TPMS_SENSITIVE_CREATE = { userAuth, data } (no sensitiveType)
    sens.sensitive.userAuth.size = 0;
    sens.sensitive.data.size = sizeof data;
    memcpy(sens.sensitive.data.buffer, data, sizeof data);
    // size: marshal length of TPMS_SENSITIVE_CREATE (auth size2 + auth, data size2 + data)
    // = 2+0 + 2+4 = 8
    sens.size = 2 + 0 + 2 + sizeof data;

    TPM2B_PUBLIC inpub; memset(&inpub, 0, sizeof inpub);
    inpub.publicArea = tpl;
    uint8_t mbuf[512]; uint64_t mw = 0;
    rc = Tss2_MU_TPMT_PUBLIC_Marshal(&tpl, mbuf, sizeof mbuf, &mw);
    if (rc) { fprintf(stderr, "MU marshal: 0x%x %s\n", rc, Tss2_RC_Decode(rc)); return 1; }
    inpub.size = (UINT16)mw;

    TPM2B_PRIVATE *opriv = NULL;
    TPM2B_PUBLIC *opub = NULL;
    TPM2B_CREATION_DATA *ocd = NULL;
    TPM2B_DIGEST *och = NULL;
    TPMT_TK_CREATION *otk = NULL;

    rc = Esys_Create(esys, parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &sens, &inpub, &outside, &cpcr,
                     &opriv, &opub, &ocd, &och, &otk);
    if (rc) {
        fprintf(stderr, "Create(attrs=0x%x): 0x%08x\n", want_attrs, rc);
        TSS2_RC_INFO info;
        if (Tss2_RC_DecodeInfo(rc, &info))
            fprintf(stderr, "  layer=%d format=%d error=0x%08x param=%d\n", info.layer, info.format, info.error, info.parameter);
        fprintf(stderr, "  decode: %s\n", Tss2_RC_Decode(rc));
        return 2;
    }
    printf("Create OK: private=%u bytes, public=%u bytes\n", opriv->size, opub->size);
    Esys_Free(opriv); Esys_Free(opub); Esys_Free(ocd); Esys_Free(och); Esys_Free(otk);
    Esys_Finalize(&esys);
    return 0;
}
