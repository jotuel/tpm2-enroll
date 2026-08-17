#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <getopt.h>
#include <stdbool.h>
#include <pwd.h>
#include <sys/types.h>

#include "tpm2_util.h"

static void print_usage(const char *progname, bool unenroll_mode) {
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -u, --user USERNAME     Target username (default: current logged-in user)\n");
    printf("  -o, --out PATH          Output path for sealed TPM blob file\n");
    if (unenroll_mode) {
        printf("  -f, --force, -y, --yes  Skip confirmation prompt\n");
    } else {
        printf("  -s, --skip-pcr          Skip TPM PCR 7 binding (for testing/development)\n");
        printf("  -t, --test              Perform test unseal immediately after sealing\n");
        printf("  -w, --wipe, --unenroll  Wipe and remove existing enrolled TPM credentials\n");
        printf("  -f, --force, -y, --yes  Skip confirmation prompt when wiping\n");
    }
    printf("  -h, --help              Show this help message\n");
}

static char *get_input_passphrase(const char *prompt) {
    struct termios old_flags, new_flags;
    char *pass = NULL;
    size_t len = 0;

    printf("%s", prompt);
    fflush(stdout);

    /* Disable terminal echo */
    if (tcgetattr(STDIN_FILENO, &old_flags) != 0) {
        return NULL;
    }
    new_flags = old_flags;
    new_flags.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_flags) != 0) {
        return NULL;
    }

    ssize_t read_len = getline(&pass, &len, stdin);

    /* Restore terminal settings */
    tcsetattr(STDIN_FILENO, TCSANOW, &old_flags);
    printf("\n");

    if (read_len <= 0 || !pass) {
        free(pass);
        return NULL;
    }

    /* Strip newline */
    pass[strcspn(pass, "\r\n")] = '\0';
    return pass;
}

int main(int argc, char **argv) {
    char *username = NULL;
    char *out_blob_path = NULL;
    bool skip_pcr = false;
    bool test_unseal = true;
    bool force = false;
    bool unenroll_mode = false;

    if (argv[0] && strstr(argv[0], "unenroll") != NULL) {
        unenroll_mode = true;
    }

    static struct option long_options[] = {
        {"user",     required_argument, 0, 'u'},
        {"out",      required_argument, 0, 'o'},
        {"skip-pcr", no_argument,       0, 's'},
        {"test",     no_argument,       0, 't'},
        {"wipe",     no_argument,       0, 'w'},
        {"unenroll", no_argument,       0, 'w'},
        {"force",    no_argument,       0, 'f'},
        {"yes",      no_argument,       0, 'f'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "u:o:stwwfyh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u':
                username = strdup(optarg);
                break;
            case 'o':
                out_blob_path = strdup(optarg);
                break;
            case 's':
                skip_pcr = true;
                break;
            case 't':
                test_unseal = true;
                break;
            case 'w':
                unenroll_mode = true;
                break;
            case 'f':
            case 'y':
                force = true;
                break;
            case 'h':
            default:
                print_usage(argv[0], unenroll_mode);
                return 0;
        }
    }

    if (!username) {
        uid_t uid = getuid();
        struct passwd *pw = getpwuid(uid);
        if (pw && pw->pw_name) {
            username = strdup(pw->pw_name);
        } else {
            fprintf(stderr, "Error: Could not determine username. Use --user <name>\n");
            return 1;
        }
    }

    char default_blob[512];
    if (!out_blob_path) {
        if (getuid() == 0) {
            tpm2_get_default_blob_path(username, default_blob, sizeof(default_blob));
        } else {
            snprintf(default_blob, sizeof(default_blob), "%s/.config/pam_bio_tpm2/sealed.blob",
                     getenv("HOME") ? getenv("HOME") : "/tmp");
        }
        out_blob_path = strdup(default_blob);
    }
    if (unenroll_mode) {
        printf("=== pam_bio_tpm2 Credentials Removal ===\n");
        printf("Target User: %s\n", username);
        printf("Blob Target: %s\n\n", out_blob_path);

        if (access(out_blob_path, F_OK) != 0) {
            printf("No sealed TPM credentials found at '%s'. Nothing to remove.\n", out_blob_path);
            free(username);
            free(out_blob_path);
            return 0;
        }

        if (!force) {
            printf("Are you sure you want to wipe sealed TPM credentials for '%s'? [y/N] ", username);
            fflush(stdout);
            char reply[32] = {0};
            if (!fgets(reply, sizeof(reply), stdin) || (reply[0] != 'y' && reply[0] != 'Y')) {
                printf("Operation canceled.\n");
                free(username);
                free(out_blob_path);
                return 0;
            }
        }

        int wipe_rc = tpm2_wipe_secret(username, out_blob_path);
        if (wipe_rc != 0) {
            fprintf(stderr, "Error: Failed to wipe sealed TPM blob (rc=%d: %s)\n",
                    wipe_rc, strerror(-wipe_rc));
            free(username);
            free(out_blob_path);
            return 1;
        }

        printf("Successfully wiped and removed sealed TPM 2.0 credentials at '%s'.\n", out_blob_path);
        free(username);
        free(out_blob_path);
        return 0;
    }


    printf("=== pam_bio_tpm2 Passphrase Enrollment ===\n");
    printf("Target User:      %s\n", username);
    printf("Sealed Blob Output: %s\n", out_blob_path);
    printf("PCR Binding:      %s\n\n", skip_pcr ? "Disabled" : "Enabled (PCR 7 - Secure Boot)");

    char *pass1 = get_input_passphrase("Enter user master passphrase (LUKS / Homed / Keyring secret): ");
    if (!pass1 || strlen(pass1) == 0) {
        fprintf(stderr, "Error: Passphrase cannot be empty.\n");
        free(pass1);
        free(username);
        free(out_blob_path);
        return 1;
    }

    char *pass2 = get_input_passphrase("Re-enter master passphrase to confirm: ");
    if (!pass2 || strcmp(pass1, pass2) != 0) {
        fprintf(stderr, "Error: Passphrases do not match.\n");
        explicit_bzero(pass1, strlen(pass1));
        if (pass2) explicit_bzero(pass2, strlen(pass2));
        free(pass1);
        free(pass2);
        free(username);
        free(out_blob_path);
        return 1;
    }
    explicit_bzero(pass2, strlen(pass2));
    free(pass2);

    size_t pass_len = strlen(pass1);
    printf("Sealing passphrase into TPM 2.0...\n");

    int seal_rc = tpm2_seal_secret(username, pass1, pass_len, out_blob_path, skip_pcr);
    if (seal_rc != 0) {
        fprintf(stderr, "Error: Failed to seal passphrase into TPM 2.0 (rc=%d)\n", seal_rc);
        explicit_bzero(pass1, pass_len);
        free(pass1);
        free(username);
        free(out_blob_path);
        return 1;
    }

    printf("Successfully sealed secret passphrase to '%s'.\n", out_blob_path);

    if (test_unseal) {
        printf("Testing TPM 2.0 secret unsealing...\n");
        char test_pass[512] = {0};
        size_t test_len = 0;

        int unseal_rc = tpm2_unseal_secret(username, out_blob_path, test_pass, sizeof(test_pass), &test_len, skip_pcr);
        if (unseal_rc != 0 || strcmp(pass1, test_pass) != 0) {
            fprintf(stderr, "FAILED: Unsealed secret test did not match sealed passphrase!\n");
            explicit_bzero(test_pass, sizeof(test_pass));
            explicit_bzero(pass1, pass_len);
            free(pass1);
            free(username);
            free(out_blob_path);
            return 1;
        }

        explicit_bzero(test_pass, sizeof(test_pass));
        printf("VERIFIED: TPM 2.0 secret unsealed and verified successfully!\n");
    }

    explicit_bzero(pass1, pass_len);
    free(pass1);
    free(username);
    free(out_blob_path);
    return 0;
}
