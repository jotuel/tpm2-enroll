#ifndef FPRINT_UTIL_H
#define FPRINT_UTIL_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Triggers fprintd D-Bus verification for the given username.
 *
 * @param username The username performing authentication.
 * @param timeout_seconds Maximum seconds to wait for fingerprint match.
 * @param debug If true, print verbose verification status messages to stderr.
 * @return 0 on verify-match, non-zero error code on failure or timeout.
 */
int fprint_verify_user(const char *username, int timeout_seconds, bool debug);

#ifdef __cplusplus
}
#endif

#endif /* FPRINT_UTIL_H */
