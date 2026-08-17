#include "tpm2_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

#define BLOB_MAGIC 0x54504D32 /* "TPM2" */

typedef struct {
    uint32_t magic;
    uint32_t priv_size;
    uint32_t pub_size;
} blob_header_t;

void tpm2_get_default_blob_path(const char *username, char *out_buf, size_t buf_len) {
    if (!username || !out_buf || buf_len == 0) return;
    snprintf(out_buf, buf_len, "/var/lib/pam_bio_tpm2/%s.blob", username);
}

static int get_primary_key(ESYS_CONTEXT *esys_ctx, ESYS_TR *primary_handle) {
    TPM2B_SENSITIVE_CREATE in_sensitive = { .size = 0, .sensitive = { .userAuth = { .size = 0 } } };
    TPM2B_PUBLIC in_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                 TPMA_OBJECT_USERWITHAUTH),
            .authPolicy = { .size = 0 },
            .parameters = {
                .rsaDetail = {
                    .symmetric = {
                        .algorithm = TPM2_ALG_AES,
                        .keyBits = { .aes = 128 },
                        .mode = { .aes = TPM2_ALG_CFB }
                    },
                    .scheme = { .scheme = TPM2_ALG_NULL },
                    .keyBits = 2048,
                    .exponent = 0
                }
            },
            .unique = { .rsa = { .size = 0 } }
        }
    };

    TPM2B_DATA outside_info = { .size = 0 };
    TPML_PCR_SELECTION creation_pcr = { .count = 0 };

    TSS2_RC rc = Esys_CreatePrimary(
        esys_ctx,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &in_sensitive,
        &in_public,
        &outside_info,
        &creation_pcr,
        primary_handle,
        NULL, NULL, NULL, NULL
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_CreatePrimary failed: 0x%x (%s)\n",
                rc, Tss2_RC_Decode(rc));
        return -1;
    }
    return 0;
}
static void get_pcr7_selection(TPML_PCR_SELECTION *pcr_selection) {
    pcr_selection->count = 1;
    pcr_selection->pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_selection->pcrSelections[0].sizeofSelect = 3;
    pcr_selection->pcrSelections[0].pcrSelect[0] = 0x80; /* Bit 7 = PCR 7 */
    pcr_selection->pcrSelections[0].pcrSelect[1] = 0x00;
    pcr_selection->pcrSelections[0].pcrSelect[2] = 0x00;
}

static int create_pcr7_policy_digest(ESYS_CONTEXT *esys_ctx, TPM2B_DIGEST **out_policy_digest) {
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL };

    TSS2_RC rc = Esys_StartAuthSession(
        esys_ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        NULL,
        TPM2_SE_TRIAL,
        &symmetric,
        TPM2_ALG_SHA256,
        &session
    );
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_StartAuthSession (TRIAL) failed: 0x%x (%s)\n",
                rc, Tss2_RC_Decode(rc));
        return -1;
    }

    TPML_PCR_SELECTION pcr_selection;
    get_pcr7_selection(&pcr_selection);
    TPM2B_DIGEST pcr_digest = { .size = 0 };

    rc = Esys_PolicyPCR(
        esys_ctx,
        session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcr_digest,
        &pcr_selection
    );
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_PolicyPCR (TRIAL) failed: 0x%x (%s)\n",
                rc, Tss2_RC_Decode(rc));
        Esys_FlushContext(esys_ctx, session);
        return -1;
    }

    rc = Esys_PolicyGetDigest(
        esys_ctx,
        session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        out_policy_digest
    );
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_PolicyGetDigest failed: 0x%x (%s)\n",
                rc, Tss2_RC_Decode(rc));
        Esys_FlushContext(esys_ctx, session);
        return -1;
    }

    Esys_FlushContext(esys_ctx, session);
    return 0;
}


int tpm2_seal_secret(const char *username,
                     const char *passphrase,
                     size_t passphrase_len,
                     const char *out_blob_path,
                     bool skip_pcr) {
    /* skip_pcr: if false, binds object to PCR 7 policy */
    if (!username || !passphrase || passphrase_len == 0 || !out_blob_path) {
        return -EINVAL;
    }

    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_RC rc = Esys_Initialize(&esys_ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_Initialize failed: 0x%x\n", rc);
        return -EIO;
    }

    ESYS_TR primary_handle = ESYS_TR_NONE;
    if (get_primary_key(esys_ctx, &primary_handle) != 0) {
        Esys_Finalize(&esys_ctx);
        return -EIO;
    }

    TPM2B_SENSITIVE_CREATE in_sensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0 },
            .data = { .size = (uint16_t)passphrase_len }
        }
    };
    if (passphrase_len > sizeof(in_sensitive.sensitive.data.buffer)) {
        Esys_FlushContext(esys_ctx, primary_handle);
        Esys_Finalize(&esys_ctx);
        return -EINVAL;
    }
    memcpy(in_sensitive.sensitive.data.buffer, passphrase, passphrase_len);

    TPM2B_PUBLIC in_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT),
            .authPolicy = { .size = 0 },
            .parameters = {
                .keyedHashDetail = {
                    .scheme = { .scheme = TPM2_ALG_NULL }
                }
            },
            .unique = { .keyedHash = { .size = 0 } }
        }
    };
    TPM2B_DIGEST *policy_digest = NULL;
    if (!skip_pcr) {
        if (create_pcr7_policy_digest(esys_ctx, &policy_digest) != 0) {
            Esys_FlushContext(esys_ctx, primary_handle);
            Esys_Finalize(&esys_ctx);
            return -EIO;
        }
        in_public.publicArea.authPolicy = *policy_digest;
        Esys_Free(policy_digest);
    } else {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    }


    TPM2B_DATA outside_info = { .size = 0 };
    TPML_PCR_SELECTION creation_pcr = { .count = 0 };

    TPM2B_PRIVATE *out_private = NULL;
    TPM2B_PUBLIC *out_public = NULL;

    rc = Esys_Create(
        esys_ctx,
        primary_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &in_sensitive,
        &in_public,
        &outside_info,
        &creation_pcr,
        &out_private,
        &out_public,
        NULL, NULL, NULL
    );

    // Clean sensitive input memory immediately
    explicit_bzero(&in_sensitive, sizeof(in_sensitive));

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_Create failed: 0x%x (%s)\n",
                rc, Tss2_RC_Decode(rc));
        Esys_FlushContext(esys_ctx, primary_handle);
        Esys_Finalize(&esys_ctx);
        return -EIO;
    }

    /* Marshal private and public parts */
    uint8_t priv_buf[4096];
    uint8_t pub_buf[4096];
    size_t priv_offset = 0;
    size_t pub_offset = 0;

    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(out_private, priv_buf, sizeof(priv_buf), &priv_offset);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Free(out_private);
        Esys_Free(out_public);
        Esys_FlushContext(esys_ctx, primary_handle);
        Esys_Finalize(&esys_ctx);
        return -EIO;
    }

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(out_public, pub_buf, sizeof(pub_buf), &pub_offset);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Free(out_private);
        Esys_Free(out_public);
        Esys_FlushContext(esys_ctx, primary_handle);
        Esys_Finalize(&esys_ctx);
        return -EIO;
    }

    /* Ensure parent directories exist */
    char parent_dir[512];
    snprintf(parent_dir, sizeof(parent_dir), "%s", out_blob_path);
    char *last_slash = strrchr(parent_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(parent_dir, 0700);
    }

    FILE *f = fopen(out_blob_path, "wb");
    if (!f) {
        perror("[pam_bio_tpm2] Failed to open blob file for writing");
        Esys_Free(out_private);
        Esys_Free(out_public);
        Esys_FlushContext(esys_ctx, primary_handle);
        Esys_Finalize(&esys_ctx);
        return -errno;
    }
    chmod(out_blob_path, 0600);

    blob_header_t header = {
        .magic = BLOB_MAGIC,
        .priv_size = (uint32_t)priv_offset,
        .pub_size = (uint32_t)pub_offset
    };

    fwrite(&header, sizeof(header), 1, f);
    fwrite(priv_buf, 1, priv_offset, f);
    fwrite(pub_buf, 1, pub_offset, f);
    fclose(f);

    Esys_Free(out_private);
    Esys_Free(out_public);
    Esys_FlushContext(esys_ctx, primary_handle);
    Esys_Finalize(&esys_ctx);

    return 0;
}

int tpm2_unseal_secret(const char *username,
                       const char *blob_path,
                       char *out_passphrase,
                       size_t max_len,
                       size_t *out_len,
                       bool skip_pcr) {
    /* skip_pcr: if false, evaluates PCR 7 policy session */
    if (!username || !blob_path || !out_passphrase || max_len == 0) {
        return -EINVAL;
    }

    FILE *f = fopen(blob_path, "rb");
    if (!f) {
        return -ENOENT;
    }

    blob_header_t header;
    if (fread(&header, sizeof(header), 1, f) != 1 || header.magic != BLOB_MAGIC) {
        fclose(f);
        return -EBADMSG;
    }

    uint8_t *priv_buf = malloc(header.priv_size);
    uint8_t *pub_buf = malloc(header.pub_size);
    if (!priv_buf || !pub_buf) {
        free(priv_buf);
        free(pub_buf);
        fclose(f);
        return -ENOMEM;
    }

    if (fread(priv_buf, 1, header.priv_size, f) != header.priv_size ||
        fread(pub_buf, 1, header.pub_size, f) != header.pub_size) {
        free(priv_buf);
        free(pub_buf);
        fclose(f);
        return -EIO;
    }
    fclose(f);

    TPM2B_PRIVATE out_private;
    TPM2B_PUBLIC out_public;
    size_t priv_offset = 0;
    size_t pub_offset = 0;

    TSS2_RC rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(priv_buf, header.priv_size, &priv_offset, &out_private);
    free(priv_buf);
    if (rc != TSS2_RC_SUCCESS) {
        free(pub_buf);
        return -EIO;
    }

    rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_buf, header.pub_size, &pub_offset, &out_public);
    free(pub_buf);
    if (rc != TSS2_RC_SUCCESS) {
        return -EIO;
    }

    ESYS_CONTEXT *esys_ctx = NULL;
    rc = Esys_Initialize(&esys_ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        return -EIO;
    }

    ESYS_TR primary_handle = ESYS_TR_NONE;
    if (get_primary_key(esys_ctx, &primary_handle) != 0) {
        Esys_Finalize(&esys_ctx);
        return -EIO;
    }

    ESYS_TR object_handle = ESYS_TR_NONE;
    rc = Esys_Load(
        esys_ctx,
        primary_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &out_private,
        &out_public,
        &object_handle
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_Load failed: 0x%x (%s)\n",
                rc, Tss2_RC_Decode(rc));
        Esys_FlushContext(esys_ctx, primary_handle);
        Esys_Finalize(&esys_ctx);
        return -EIO;
    }

    ESYS_TR auth_session = ESYS_TR_PASSWORD;
    if (!skip_pcr) {
        TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL };
        rc = Esys_StartAuthSession(
            esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            NULL,
            TPM2_SE_POLICY,
            &symmetric,
            TPM2_ALG_SHA256,
            &auth_session
        );
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "[pam_bio_tpm2] Esys_StartAuthSession (POLICY) failed: 0x%x (%s)\n",
                    rc, Tss2_RC_Decode(rc));
            Esys_FlushContext(esys_ctx, object_handle);
            Esys_FlushContext(esys_ctx, primary_handle);
            Esys_Finalize(&esys_ctx);
            return -EIO;
        }

        TPML_PCR_SELECTION pcr_selection;
        get_pcr7_selection(&pcr_selection);
        TPM2B_DIGEST pcr_digest = { .size = 0 };

        rc = Esys_PolicyPCR(
            esys_ctx,
            auth_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &pcr_digest,
            &pcr_selection
        );
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "[pam_bio_tpm2] Esys_PolicyPCR (POLICY) failed: 0x%x (%s)\n",
                    rc, Tss2_RC_Decode(rc));
            Esys_FlushContext(esys_ctx, auth_session);
            Esys_FlushContext(esys_ctx, object_handle);
            Esys_FlushContext(esys_ctx, primary_handle);
            Esys_Finalize(&esys_ctx);
            return -EACCES;
        }
    }

    TPM2B_SENSITIVE_DATA *unsealed_data = NULL;
    rc = Esys_Unseal(
        esys_ctx,
        object_handle,
        auth_session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &unsealed_data
    );

    if (auth_session != ESYS_TR_PASSWORD && auth_session != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, auth_session);
    }

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "[pam_bio_tpm2] Esys_Unseal failed: 0x%x (%s)\n",
                rc, Tss2_RC_Decode(rc));
        Esys_FlushContext(esys_ctx, object_handle);
        Esys_FlushContext(esys_ctx, primary_handle);
        Esys_Finalize(&esys_ctx);
        return -EACCES;
    }

    size_t len = unsealed_data->size;
    if (len >= max_len) {
        len = max_len - 1;
    }

    memcpy(out_passphrase, unsealed_data->buffer, len);
    out_passphrase[len] = '\0';
    if (out_len) {
        *out_len = len;
    }

    /* Zero out sensitive memory */
    explicit_bzero(unsealed_data->buffer, unsealed_data->size);
    Esys_Free(unsealed_data);

    Esys_FlushContext(esys_ctx, object_handle);
    Esys_FlushContext(esys_ctx, primary_handle);
    Esys_Finalize(&esys_ctx);

    return 0;
}
