#ifndef TPM2_UTIL_H
#define TPM2_UTIL_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Seals a secret passphrase into TPM 2.0 object and writes the sealed blob file.
 *
 * @param username The target user.
 * @param passphrase Secret passphrase to seal.
 * @param passphrase_len Length of the passphrase.
 * @param out_blob_path File path where the sealed data blob will be written.
 * @param skip_pcr If true, skip PCR 7 binding (useful for testing or non-boot-bound environments).
 * @return 0 on success, negative error code on failure.
 */
int tpm2_seal_secret(const char *username,
                     const char *passphrase,
                     size_t passphrase_len,
                     const char *out_blob_path,
                     bool skip_pcr);

/**
 * Unseals a secret passphrase from a TPM 2.0 sealed blob file.
 *
 * @param username The target user.
 * @param blob_path File path of the sealed data blob.
 * @param out_passphrase Output buffer to receive the unsealed passphrase.
 * @param max_len Maximum capacity of out_passphrase buffer.
 * @param out_len Pointer to store actual length of unsealed passphrase.
 * @param skip_pcr If true, skip PCR 7 policy session during unseal.
 * @return 0 on success, negative error code on failure.
 */
int tpm2_unseal_secret(const char *username,
                       const char *blob_path,
                       char *out_passphrase,
                       size_t max_len,
                       size_t *out_len,
                       bool skip_pcr);

/**
 * Utility function to obtain the default blob path for a user.
 *
 * @param username Target username.
 * @param out_buf Buffer to store default path string.
 * @param buf_len Buffer capacity.
 */
void tpm2_get_default_blob_path(const char *username, char *out_buf, size_t buf_len);

/**
 * Securely wipes and removes a user's sealed TPM 2.0 blob file.
 *
 * @param username Target username.
 * @param blob_path File path of the sealed data blob (or NULL for default).
 * @return 0 on success, -ENOENT if not found, negative errno on failure.
 */
int tpm2_wipe_secret(const char *username, const char *blob_path);

#ifdef __cplusplus
}
#endif

#endif /* TPM2_UTIL_H */
