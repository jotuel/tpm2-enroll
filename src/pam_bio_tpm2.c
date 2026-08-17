#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdbool.h>

#include "tpm2_util.h"
#include "fprint_util.h"

typedef struct {
    bool debug;
    bool skip_pcr;
    int timeout_seconds;
    char custom_blob_path[512];
} pam_options_t;

static void parse_pam_args(int argc, const char **argv, pam_options_t *opts) {
    opts->debug = false;
    opts->skip_pcr = false;
    opts->timeout_seconds = 15;
    opts->custom_blob_path[0] = '\0';

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            opts->debug = true;
        } else if (strcmp(argv[i], "skip_pcr") == 0) {
            opts->skip_pcr = true;
        } else if (strncmp(argv[i], "timeout=", 8) == 0) {
            opts->timeout_seconds = atoi(argv[i] + 8);
        } else if (strncmp(argv[i], "blob_path=", 10) == 0) {
            snprintf(opts->custom_blob_path, sizeof(opts->custom_blob_path), "%s", argv[i] + 10);
        }
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    pam_options_t opts;
    parse_pam_args(argc, argv, &opts);

    const char *username = NULL;
    int ret = pam_get_user(pamh, &username, NULL);
    if (ret != PAM_SUCCESS || !username || strlen(username) == 0) {
        if (opts.debug) {
            pam_syslog(pamh, LOG_ERR, "Failed to get target user from PAM context");
        }
        return PAM_USER_UNKNOWN;
    }

    if (opts.debug) {
        pam_syslog(pamh, LOG_INFO, "Initiating biometric & TPM2 authentication for user '%s'", username);
    }

    /* 1. Resolve TPM blob path */
    char blob_path[512];
    if (opts.custom_blob_path[0] != '\0') {
        snprintf(blob_path, sizeof(blob_path), "%s", opts.custom_blob_path);
    } else {
        tpm2_get_default_blob_path(username, blob_path, sizeof(blob_path));
    }

    /* Check if blob file exists before initiating fingerprint scan */
    if (access(blob_path, R_OK) != 0) {
        if (opts.debug) {
            pam_syslog(pamh, LOG_WARNING, "Sealed TPM blob for user '%s' not found at '%s'", username, blob_path);
        }
        return PAM_AUTH_ERR;
    }

    /* 2. Verify fingerprint scan via fprintd D-Bus */
    if (opts.debug) {
        pam_syslog(pamh, LOG_INFO, "Prompting user for fingerprint scan via fprintd...");
    }

    int verify_rc = fprint_verify_user(username, opts.timeout_seconds, opts.debug);
    if (verify_rc != 0) {
        pam_syslog(pamh, LOG_NOTICE, "Fingerprint verification failed for user '%s' (rc=%d)", username, verify_rc);
        return PAM_AUTH_ERR;
    }

    if (opts.debug) {
        pam_syslog(pamh, LOG_INFO, "Fingerprint match confirmed for user '%s'. Unsealing TPM 2.0 secret...", username);
    }

    /* 3. Unseal passphrase from TPM 2.0 */
    char passphrase[512] = {0};
    size_t pass_len = 0;

    int unseal_rc = tpm2_unseal_secret(username, blob_path, passphrase, sizeof(passphrase), &pass_len, opts.skip_pcr);
    if (unseal_rc != 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to unseal TPM 2.0 secret for user '%s' (rc=%d)", username, unseal_rc);
        explicit_bzero(passphrase, sizeof(passphrase));
        return PAM_AUTH_ERR;
    }

    /* 4. Inject unsealed passphrase into PAM_AUTHTOK */
    ret = pam_set_item(pamh, PAM_AUTHTOK, passphrase);

    /* Zero memory immediately */
    explicit_bzero(passphrase, sizeof(passphrase));

    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to set PAM_AUTHTOK for user '%s': %s", username, pam_strerror(pamh, ret));
        return PAM_AUTH_ERR;
    }

    if (opts.debug) {
        pam_syslog(pamh, LOG_INFO, "Successfully authenticated user '%s' and set PAM_AUTHTOK", username);
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    pam_options_t opts;
    parse_pam_args(argc, argv, &opts);

    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) == PAM_SUCCESS && username && opts.debug) {
        pam_syslog(pamh, LOG_INFO, "pam_sm_open_session active for user '%s'", username);
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
