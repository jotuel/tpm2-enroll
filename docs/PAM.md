# PAM Configuration

PAM configuration examples for integrating `pam_bio_tpm2.so` across display managers (**greetd / COSMIC Desktop**, GDM, SDDM) and encrypted home directory engines (`systemd-homed`, `pam_mount`, `fscrypt`).

---

## 1. `greetd` + `cosmic-session` Integration

On systems running **COSMIC Desktop** with `greetd` PAM authentication is handled by `/etc/pam.d/greetd`.

### Configuration

Edit `/etc/pam.d/greetd`:

```ini
#%PAM-1.0

# 1. Environment & fail delay
auth       required     pam_securetty.so
auth       requisite    pam_nologin.so

# 2. Biometric & TPM 2.0 Passphrase Injection
#    fprintd verifies fingerprint -> TPM2 unseals master passphrase into PAM_AUTHTOK
auth       sufficient   pam_bio_tpm2.so debug

# 3. Standard password fallback if fingerprint fails or times out
auth       required     pam_unix.so try_first_pass nullok

# 4. Optional: Pass PAM_AUTHTOK to GNOME Keyring / secret portal
auth       optional     pam_gnome_keyring.so use_first_pass

account    include      system-local-login

password   include      system-local-login

# 5. Session Phase: Decrypt systemd-homed LUKS container & unlock secret portal
session    include      system-local-login
session    optional     pam_systemd_home.so
session    optional     pam_gnome_keyring.so auto_start
```

---

## 2. `/etc/pam.d/system-auth` Direct Integration

If you prefer `greetd` to inherit biometric unlock globally via `system-local-login` -> `system-auth`:

Update `/etc/pam.d/system-auth`:

```ini
#%PAM-1.0

auth       required                    pam_faillock.so      preauth
-auth      [success=3 default=ignore]  pam_systemd_home.so

# Replace pam_fprintd.so with pam_bio_tpm2.so
auth       [success=2 default=ignore]  pam_bio_tpm2.so
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc

-account   [success=1 default=ignore]  pam_systemd_home.so
account    required                    pam_unix.so
account    optional                    pam_permit.so
account    required                    pam_time.so

-password  [success=1 default=ignore]  pam_systemd_home.so
password   required                    pam_unix.so          try_first_pass nullok shadow
password   optional                    pam_permit.so

-session   optional                    pam_systemd_home.so
session    required                    pam_limits.so
session    required                    pam_unix.so
session    optional                    pam_permit.so
session    optional                    pam_gnome_keyring.so auto_start
```

---

## Verification Commands for COSMIC Desktop

After logging in:

1. **Home Directory Decryption:**
   ```bash
   df -h /home/$USER
   homectl status $USER
   ```
2. **Secret Portal / GNOME Keyring Access:**
   ```bash
   secret-tool lookup service test || echo "Keyring accessible"
   ```
3. **greetd & pam_bio_tpm2 logs:**
   ```bash
   journalctl -u greetd -e | grep pam_bio_tpm2
   ```
## 3. GDM & SDDM Configurations

### GDM (`/etc/pam.d/gdm-fingerprint`)
```ini
#%PAM-1.0
auth        attribute_silent
auth        required      pam_env.so
auth        required      pam_faildelay.so delay=2000000

auth        sufficient    pam_bio_tpm2.so
auth        required      pam_unix.so try_first_pass
auth        optional      pam_gnome_keyring.so use_first_pass

account     include       system-local-login
password    include       system-local-login

session     include       system-local-login
session     optional      pam_systemd_home.so
session     optional      pam_gnome_keyring.so auto_start
```

### SDDM (`/etc/pam.d/sddm`)
```ini
#%PAM-1.0
auth        include       system-login

auth        sufficient    pam_bio_tpm2.so
auth        optional      pam_kwallet5.so use_first_pass

account     include       system-login
password    include       system-login

session     include       system-login
session     optional      pam_systemd_home.so
session     optional      pam_kwallet5.so auto_start
```

---

## 4. Storage Engine Specific Configurations

### A. `systemd-homed` (LUKS Home Directory Containers)
In `/etc/pam.d/greetd` or `/etc/pam.d/system-auth`:
```ini
auth        sufficient    pam_bio_tpm2.so
auth        required      pam_unix.so try_first_pass

session     optional      pam_systemd_home.so
```

### B. `pam_mount` (Raw LUKS Partitions / Loopback Images)
In `/etc/pam.d/greetd` or `/etc/pam.d/system-auth`:
```ini
auth        sufficient    pam_bio_tpm2.so
auth        required      pam_unix.so try_first_pass

session     optional      pam_mount.so
```

### C. `fscrypt` (Ext4 / F2FS Kernel Native Encryption)
In `/etc/pam.d/greetd` or `/etc/pam.d/system-auth`:
```ini
auth        sufficient    pam_bio_tpm2.so
auth        required      pam_unix.so try_first_pass

session     optional      pam_fscrypt.so drop_user_key
```

---
