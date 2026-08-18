# `pam_bio_tpm2` & `tpm2-enroll`

A Linux Pluggable Authentication Module and cli tool for biometric authentication with TPM 2.0. Enables fingerprint authentication to automatically decrypt per-user encrypted home directories and unlock Keyring / Wallet secret portals during login.

---

## Why

Standard symmetric encryption requires a secret passphrase to derive decryption keys. Standard host biometric sensors (`fprintd`) returns a boolean `PAM_SUCCESS` or `PAM_AUTH_ERR` signal, **not** a key.

`pam_bio_tpm2`:
1. Performs biometric verification using `fprintd` via D-Bus.
2. Upon match, unseals the user's master encryption passphrase stored in the system TPM 2.0 chip.
3. Injects the unsealed passphrase to `PAM_AUTHTOK`.
4. Downstream session modules consume `PAM_AUTHTOK` decrypting user storage and/or unlocking keyrings.

---

## `FIDO` vs `TPM2.0`

| Feature | `systemd-homed` + FIDO2 Match-on-Chip | `libfprint` + TPM 2.0 Secret |
| :---: | :--- | :--- |
| **Hardware Required** | FIDO2 token with biometric reader | Fingerprint reader + TPM 2.0 |
| **Match Location** | Secure enclave hardware token | `fprintd` background daemon |
| **Key Derivation** | On-chip `hmac-secret` | TPM 2.0 NV/Object unseal |
| **Custom Code Needed** | None  | Required |
| **Boot Integrity Protection** | Protected by PIN / Biometric match | Bound to TPM 2.0 PCR 7 (Secure Boot) |
| **Per-User Home Support** | Native `systemd-homed` LUKS | `systemd-homed`, `pam_mount`, `fscrypt`, `ecryptfs` |
| **Detailed Spec** | [See `docs/FIDO2.md`](docs/FIDO2.md) | [See `docs/TPM2.md`](docs/TPM2.md) |

---

## Quick Start

### 1. Build and Install
```bash
make
sudo make install
```
Installs:
* `/lib/security/pam_bio_tpm2.so` (PAM Module)
* `/usr/local/bin/tpm2-enroll` / `pam-bio-tpm2-enroll` (Enrollment CLI)
* `/usr/local/bin/tpm2-unenroll` / `pam-bio-tpm2-unenroll` (Removal CLI)

### 2. Enroll Passphrase to TPM 2.0
```bash
tpm2-enroll --user $USER
```
* Prompts for your home directory / keyring master passphrase.
* Seals the passphrase into TPM 2.0 bound to PCR 7 (Secure Boot state & certificates).

### 3. Remove / Unenroll Passphrase (Optional)
To securely wipe the sealed credentials:
```bash
tpm2-unenroll --user $USER
# Or: tpm2-enroll --wipe --user $USER
```
### 4. Configure PAM
Add `pam_bio_tpm2.so` before `pam_unix.so` and keyring/home modules in `/etc/pam.d/gdm-fingerprint` (or `/etc/pam.d/sddm` / `/etc/pam.d/system-auth`):

```ini
# 1. Verify fingerprint and unseal passphrase into PAM_AUTHTOK
auth        sufficient    pam_bio_tpm2.so

# 2. Password fallback
auth        required      pam_unix.so try_first_pass

# 3. Inject into keyring / secret portal
auth        optional      pam_gnome_keyring.so use_first_pass

# 4. Open session and decrypt per-user home directory + keyring
session     required      pam_unix.so
session     optional      pam_systemd_home.so
session     optional      pam_gnome_keyring.so auto_start
```
*(For complete setup options, see [`docs/PAM.md`](docs/PAM.md))*

---

## Documentation

- [`docs/FIDO2.md`](docs/FIDO2.md) - Hardware FIDO2 + systemd-homed guide.
- [`docs/TPM2.md`](docs/TPM2.md) - Deep dive architecture for host fprintd + TPM 2.0.
- [`docs/PAM.md`](docs/PAM.md) - Comprehensive PAM stack configurations.

---

