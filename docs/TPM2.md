# Fingerprint Sensor (`libfprint`) + TPM 2.0 Secret (`pam_bio_tpm2`)

Architecture, cryptographic protocols and implementation details for unlocking encrypted home directories and secret keyrings using fingerprint reader and TPM 2.0.

---

## 1. Why

Fingerprint sensors operate via host-side or sensor-side comparison driven by `fprintd` over D-Bus. 

When a user touches the sensor:
* `fprintd` verifies the scan against enrolled fingerprint templates.
* This returns a boolean (`verify-match`) over D-Bus.
* Modules require a passphrase to decrypt home containers and/or unlock keyrings.

`pam_bio_tpm2` solves this by a TPM 2.0 sealed secret passphrase.

---

## 2. Protocol & TPM 2.0

```
 ┌─────────────────────────┐
 │ User enrolls fingerprint│
 └───────────┬─────────────┘
             │
             ▼
 ┌──────────────────────────────────────────────────────────┐
 │ 1. Generate High-Entropy Master Secret Passphrase        │
 │ 2. Add Passphrase to LUKS / systemd-homed / Keyring      │
 └───────────┬──────────────────────────────────────────────┘
             │
             ▼
 ┌──────────────────────────────────────────────────────────┐
 │ 3. Create TPM 2.0 Primary Key                            |
 │ 4. Create Sealed Key Object containing Master Passphrase │
 │ 5. Bind Policy to PCR 7 (Secure Boot Integrity)           │
 │ 6. Write Sealed Blob to persistent storage (~/.tpm2_bio) │
 └──────────────────────────────────────────────────────────┘
```

### Authentication Flow:

```
                   +------------------------+
                   |  PAM Login Triggered   |
                   +-----------+------------+
                               |
                               v
                   +------------------------+
                   | pam_bio_tpm2_auth()    |
                   +-----------+------------+
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
+-----------------------+             +------------------------+
| fprintd D-Bus Verify  |             | Read System TPM 2.0    |
| (Verify user finger)  |             | PCR State (PCR 7)      |
+-----------+-----------+             +-----------+------------+
            |                                     |
            +------------------+------------------+
                               | Both Valid
                               v
                   +------------------------+
                   | TPM2_Unseal() Object   |
                   | -> Master Passphrase   |
                   +-----------+------------+
                               |
                               v
                   +------------------------+
                   | Inject into            |
                   | PAM_AUTHTOK            |
                   +-----------+------------+
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
+-----------------------+             +------------------------+
| pam_systemd_home.so / |             | pam_gnome_keyring.so / |
| pam_mount.so          |             | pam_kwallet5.so        |
| Decrypts Home Container|            | Unlocks Secret Portal  |
+-----------------------+             +------------------------+
```

---

## 3. PCR Binding Policy

To prevent evil maid attacks while maintaining resilience across system updates, the TPM object is bound to **PCR 7**:

| PCR Index | Description | Security Function |
| :---: | :--- | :--- |
| **7** | Secure Boot State & Certificates | Enforces Secure Boot; blocks untrusted kernels, bootloaders, or disabled Secure Boot |

### Why PCR 7 (and not PCR 0, 4, 11)?

* **PCR 0 / 4 / 11** record exact binary hashes of the UEFI firmware, bootloader (`systemd-bootx64.efi`), and kernel image. Whenever `systemd-boot-update.service` or kernel updates are applied, these measurements change, breaking auto-unseal and requiring manual re-enrollment.
* **PCR 7** measures the **Secure Boot enforcement state and authorized certificate database (`PK`, `KEK`, `db`, `dbx`)**, rather than volatile binary hashes.
* With tools like `sbctl` automatically signing new bootloader and kernel binaries, **PCR 7 remains constant across system updates** while guaranteeing that any unsigned, tampered, or evil maid bootloader cannot unseal the secret.

If Secure Boot is disabled or modified certificates are used, PCR 7 changes and the TPM 2.0 chip refuses to unseal the secret.

## 4. Components

1. **`pam_bio_tpm2.so`**: The shared PAM library placed in `/lib/security/`.
   - `pam_sm_authenticate`: Talks to `fprintd` D-Bus service, unseals TPM secret, sets `PAM_AUTHTOK`.
   - `pam_sm_open_session`: Cleans up transient state, ensures keyring synchronization.
2. **`pam-bio-tpm2-enroll`**: Command-line administration tool.
   - Enrolls user passphrase into TPM 2.0.
   - Saves sealed blob to `/var/lib/pam_bio_tpm2/<username>.blob` or `~/.config/pam_bio_tpm2/sealed.blob`.
   - Verifies biometric enrollment status with `fprintd`.

---

## 5. Failure & Safety

1. **Fingerprint Rejection / Timeout:**
   - PAM returns `PAM_AUTH_ERR`.
   - Control passes down to `pam_unix.so` for standard password entry.
2. **TPM PCR Mismatch (Secure Boot Disabled / Tampered Certificates):**
   - TPM 2.0 returns `TSS2_ESYS_RC_POLICY_FAIL`.
   - `pam_bio_tpm2.so` catches error, logs warning via `pam_syslog()`, and triggers password fallback.
   - User can authenticate with standard password; secret remains protected.
3. **Memory Safety:**
   - Secrets allocated with `mlock()` to prevent paging to swap disk.
   - Buffers zeroed with `explicit_bzero()`.
