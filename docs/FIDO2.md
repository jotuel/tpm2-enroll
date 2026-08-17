# Hardware Biometric FIDO2 Token + `systemd-homed`

This document details the configuration and operational model for unlocking per-user encrypted home directories and desktop secret keyrings using hardware-based biometric verification (e.g., YubiKey Bio or FIDO2 Security Key with fingerprint verification).

---

## 1. Overview

### How Match-on-Chip Works
In hardware match-on-chip FIDO2 keys:
1. The fingerprint sensor and matcher reside inside the isolated hardware security element of the FIDO2 key.
2. Fingerprint templates never touch host memory or host operating system APIs.
3. Upon a valid fingerprint match, the FIDO2 key evaluates the `hmac-secret` extension and outputs a 256-bit deterministic secret key derived from a seed stored inside the security element.
4. The derived secret is passed directly to `systemd-homed` / `systemd-cryptsetup` to decrypt the LUKS home image.

```
 +-------------------------+     Biometric Scan      +----------------------+
 | User touches YubiKey Bio| ---------------------> | Biometric Sensor     |
 +-------------------------+                        +----------------------+
                                                               |
                                                   Valid Fingerprint Match
                                                               v
 +-------------------------+   Deterministic Secret +----------------------+
 | Host systemd-homed LUKS | <--------------------- | FIDO2 hmac-secret    |
 +-------------------------+                        +----------------------+
```

---

## 2. System Requirements

* `systemd` v245 or newer (with `systemd-homed` enabled).
* FIDO2 security key supporting:
  * Biometric verification (`uv` / User Verification).
  * `hmac-secret` extension (supported by YubiKey 5 Bio series and compliant FIDO2 biometrics).
* `libfido2` library and `fido2-tools`.

---

## 3. Configuration

### Verify FIDO2 Token Compatibility
Insert your FIDO2 token and verify `hmac-secret` and biometric capabilities:

```bash
fido2-token -L
# Note the device path (e.g. /dev/hidrawX)

fido2-token -I /dev/hidrawX
# Confirm 'hmac-secret' is listed under extensions
# Confirm 'uv' (user verification) is supported
```

### Enroll FIDO2 Biometric Key in `systemd-homed`
Create or modify a `systemd-homed` user record to bind decryption to the FIDO2 token:

```bash
# For existing homed user:
homectl enroll $USER \
    --fido2-device=auto \
    --fido2-with-client-pin=false \
    --fido2-with-user-presence=true

# Verify user status
homectl inspect $USER
```

### Configure PAM for Keyring Auto-Unlock
`systemd-homed` automatically handles home directory LUKS activation upon successful FIDO2 verification. To ensure GNOME Keyring or KDE KWallet unlocks simultaneously:

Edit `/etc/pam.d/system-auth` or `/etc/pam.d/gdm-password`:

```ini
# PAM configuration for systemd-homed + GNOME Keyring
auth      sufficient    pam_systemd_home.so
auth      required      pam_unix.so try_first_pass
auth      optional      pam_gnome_keyring.so use_first_pass

account   required      pam_unix.so
account   optional      pam_systemd_home.so

session   required      pam_unix.so
session   optional      pam_systemd_home.so
session   optional      pam_gnome_keyring.so auto_start
```

---
