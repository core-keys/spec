# core-keys — Design (frozen 2026-08-28)

A hardware security key for SSH and FIDO2 in which the desktop and a dedicated
device must both participate in every authentication, and the device explicitly
approves each use.

Full design study (architecture comparison, threat matrix, fact-checked
sources): https://claude.ai/code/artifact/5ddf7edd-81d9-4d79-a77f-949662b43455

## Decisions (agreed with owner)

- **D1 — key split.** "The full key never exists anywhere" is a *requirement
  for SSH*, an explicit non-goal for FIDO2 (it would require 2P-ECDSA on an
  MCU — categorically rejected: Lindell17 compute-infeasible on M4/M33-class
  parts, DKLs ~100–230 KB/signature over HID, BitForge-class implementation
  risk). v1 ships the C+B backbone for both protocols; FROST 2-of-2
  Ed25519 (RFC 9591) for SSH is committed as v2. v1 key-record formats carry
  share semantics (`whole key | wrapped key | share + group pubkey`) from day
  one so FROST is an addition, not a migration.
- **D2 — approvals.** Tiered policy as first-class device state: per-use
  button default; opt-in device-side cache keyed on (credential, verified
  hostkey), ≤ 15 min, live counter on display; `is_forwarding` requests always
  take a fresh touch; FIDO2 always per-use.
- **D3 — recovery.** No seed backup in v1. Dual-track: machine-bound
  *sacrificial* desktop share (Secure Enclave / TPM-sealed); a separate cold
  recovery credential enrolled everywhere; encrypted enrollment journal;
  offline personal SSH CA issuing short-lived certs. No 2-of-3 sharing, ever
  (desktop + cold share would sign without device approval).
- **D4 — prototype hardware.** ESP32-S3 dev board (on hand, VID 0x303A
  PID 0x1001) as the *protocol mule*: native USB-OTG + TinyUSB lets it
  enumerate as the real composite device (CTAP HID 0xF1D0 + vendor HID
  0xFF00). It is NOT the final signing core (no ECC accelerator, weak FI
  story). Final target per study: nRF52840 or STM32U5 + NXP SE050 + 128×64
  OLED + button.

## Co-authorization protocol decisions (2026-08-28 — docs/coauth-protocol.md)

Settled after an adversarial review that broke the first draft (4 critical, 7
high findings, all fixed). Decisions:
- **CA-D1**: co-authorization is the AUTHENTICATED IN-SESSION Noise message, not
  a detached daemon signature over the to-be-signed bytes (the daemon never signs
  RP-/server-controlled bytes).
- **CA-D2**: SEPARATE keys — an X25519 Noise static from an ECDH-only handle,
  distinct from any Ed25519 credential/identity key.
- **CA-D3**: ship C (co-authorization) first; freeze architecture-B's interface
  (`UNLOCK{wrap_share}` + HKDF + teardown) now, implement wrapping later.
- **CA-D4**: implement SSH (daemon-initiated) co-auth first, FIDO2 second.
- Pairing = commit-reveal SAS (24-bit / 6 digits) + a device-local enroll gesture
  + proof-of-possession before pinning; adding an Nth desktop needs an existing
  daemon's approval. Honest non-goal: the SAS assumes a trusted host at pairing
  time (the host draws the code you compare against).

## Architecture (v1 = C+B, v2 adds A-for-SSH)

- Device is a standard USB CTAP2.1 authenticator (TLC-1, usage page 0xF1D0)
  and the backend of a custom ssh-agent. Second HID collection (TLC-2, vendor
  0xFF00) carries a Noise_KK channel with X25519 statics pinned at pairing. The
  vendor channel is reachable by any local process; only what is inside an
  established Noise session (or the SAS+button-gated pairing frames) is trusted —
  NO plaintext frame may change device state. (M2 review reclassified the M1
  mule's plaintext reboot/status frames as a critical vuln; see coauth-protocol
  §11 — mule keeps the reflash hatch behind a dev flag + BOOT hold, production
  removes it.) Full protocol: docs/coauth-protocol.md.
- Firmware signs only when it has an AUTHENTICATED IN-SESSION request from the
  paired desktop over the exact to-be-signed bytes, plus a button press after
  the display. Co-authorization is the Noise session itself, NOT a detached
  signature (decision D1, 2026-08-28) — the daemon never signs RP-/server-
  controlled bytes.
  - FIDO2 (device-initiated): device builds authenticatorData, asks the daemon
    to APPROVE over the session, shows rpId, button, signs.
  - SSH (daemon-initiated): daemon (the ssh-agent) sends the exact userauth blob
    over the session; firmware runs a strict three-shape parser (RFC 4252 |
    publickey-hostbound | SSHSIG allowed-namespace), checks the hostbound host
    key, shows user@nickname, button, signs.
- SSH destination display is *verified*, not asserted: prefer
  publickey-hostbound-v00@openssh.com (server host key inside signed bytes,
  OpenSSH ≥ 8.9) and require a verified session-bind@openssh.com binding
  otherwise; explicit "destination unverified" state for servers with neither;
  FORWARDED banner when is_forwarding is set.
- At rest (B): credential store wrapped under KDF(SE secret, desktop share);
  share delivered per session unlock over Noise, RAM-only on device.
- Keys: FIDO2 ES256 in SE050 (EdDSA also offered); SSH plain ssh-ed25519 via
  the agent (server compat to OpenSSH 6.5; FROST-compatible signature format).
  signCount=0 on the wire; SE-backed internal counters.
- FROST v2 nonce discipline (non-negotiable): never deterministic;
  H(TRNG(32) ‖ monotonic_counter ‖ share); one concurrent session; state wiped
  on abort/cancel/power-glitch; desktop must never deal shares (device-side
  dealing or DKG).

## Honest threat claims

Buys over a YubiKey+PIN: stolen/lab-attacked device is cryptographically
worthless (wrapped store; FROST share in v2); location-binding to the paired
desktop; instant desktop-share revocation; per-signature audit log; honest
approval display. Does NOT buy: protection against desktop malware co-signing
in-session (the desktop half participates whenever the user does), nor
phishing resistance beyond WebAuthn/SSH themselves. The button alone approves
*a* signature; only the display makes it *the* signature — display mandatory.

## Milestones

1. **M1 (mule):** ESP32-S3 enumerates as composite CTAP+vendor HID; minimal
   CTAP2 getInfo/makeCredential/getAssertion; desktop daemon skeleton (Rust);
   co-auth round-trip over the vendor channel with keepalives; button = boot
   button; works against Chrome + the on-hub YubiKey as interop reference.
   - **DONE (verified on HW 2026-08-28):** composite enumeration (usage pages
     0xF1D0 + 0xFF00), CTAPHID INIT/PING/CBOR framing + fragmentation, CTAP2
     authenticatorGetInfo — validated with `fido2-token -I` and hidapi PING +
     vendor loopback. Firmware: `firmware/mule-esp32s3` (ESP-IDF v5.5.1).
   - **DONE — display (verified on HW 2026-08-28):** ST7789 1.9" 170x320 over
     the i80 parallel bus (LilyGO T-Display-S3); boot splash + live status
     screen (design copper/teal palette, Menlo-derived 8x16 font). The screen
     updates on each CTAP request (ui_note_ctap hook). Confirmed via a vendor
     STATUS query (`lcd_ok=1`, framebuffer 108800 B in internal RAM). This is
     the WYSIWYS approval surface the design requires.
   - **Remaining:** makeCredential/getAssertion, clientPIN, keepalives, the
     desktop daemon (Rust), the real co-auth handshake over the vendor channel,
     and the per-operation approval prompt on the display (M2).
2. **M2:** custom ssh-agent with session-bind verification + hostbound
   preference; strict blob parser on device; approval policy engine + journal.
3. **M3:** pairing ceremony (Noise statics, QR/display), wrap layer, audit log.
4. **M4:** protocol freeze; Tamarin/ProVerif model of pairing+co-auth+rotation;
   fuzzing rig (CBOR/CTAPHID/vendor/SSH parsers); FIDO conformance self-tests.
5. **M5:** nRF52840+SE050+OLED hardware; port; FROST-for-SSH module (v2, D1).

Toolchain: ESP-IDF v5.5.1 (mule firmware, TinyUSB composite HID); Rust for the
desktop daemon and the shared protocol crate (no_std core reused on the final
nRF52840 firmware).

## Hardware / flashing notes (the on-hand ESP32-S3)

- ESP32-S3 rev 0.2, 16 MB flash, 8 MB PSRAM, MAC 44:1b:f6:d9:c8:68.
- Native USB (GPIO19/20) is the download path (`/dev/cu.usbmodem1401`,
  USB-Serial-JTAG) — but the mule firmware takes it over with TinyUSB, so that
  port disappears once the app runs. Flash with `firmware/mule-esp32s3/flash.sh`.
- Board is a **LilyGO T-Display-S3** (ESP32-S3R8): ST7789 on the i80 parallel
  bus. Pins: data D0-D7 = GPIO 39,40,41,42,45,46,47,48; WR=8 RD=9 DC=7 CS=6
  RST=5; backlight=38; **PWR_EN=GPIO15 must be HIGH** or the panel is dark;
  display inversion ON; 170-wide panel sits at column offset 35 in the 240-wide
  ST7789 RAM. Octal PSRAM exists but is NOT enabled — the 108 KB framebuffer
  lives in internal RAM (plenty of headroom).
- **Reflash escape hatch:** the running mule accepts a 4-byte magic
  (`C0 DE B0 07`) on the vendor HID channel and reboots into ROM serial-download
  mode. Handled in the USB-driver task (`ck_usb_rx_enqueue`), so it survives a
  hung worker task. Run `tools/reboot-to-download.py` (needs `pip install
  hidapi`).
- **The reflash gotcha (important):** esptool's reset over this board's
  USB-Serial-JTAG keeps landing in the bootloader instead of running the app
  (DTR->GPIO0 polarity + the USB link resetting itself). After flashing, the
  reliable way to RUN the new firmware is a **physical power cycle** (unplug ~5s,
  replug). So the loop is: `reboot-to-download.py` -> flash -> power-cycle.
  Improving the software run-reset is a TODO (try the esptool USB-JTAG reset
  class / correct DTR polarity) to make iteration fully hands-free.
- Font is generated from a system TTF by `tools/gen_font.py` (Menlo 13px ->
  `main/font8x16.h`); regenerate if the glyphs need changing.
- The "ESP32S3_DEV" port (`/dev/cu.usbmodemC04E30126AE43`) is a DIFFERENT USB
  device, not this board — ignore it.
