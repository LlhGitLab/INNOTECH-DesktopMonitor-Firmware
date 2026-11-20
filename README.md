# INNOTECH Desktop Monitor Firmware

Signed firmware distribution for INNOTECH desktop printer monitors.

- Primary releases: https://github.com/LlhGitLab/INNOTECH-DesktopMonitor-Firmware/releases
- CNB mirror: https://cnb.cool/INNOTECH8/INNOTECH-DesktopMonitor-Firmware/-/releases
- Device policy: GitHub first, CNB fallback after bounded failure or sustained slow transfer.
- ESP32-C3 sec2 verification key: [keys/ota-sec2-public.pem](keys/ota-sec2-public.pem). The [legacy verification key](keys/ota-public.pem) applies to older board profiles.

### ESP32-C3 protected updates

Each sec2 release distributes one signed manifest, one encrypted firmware image and up to 256 `keygroup-xx.bin` files for up to 10,000 enrolled monitors. A monitor downloads its group when it installs an update and verifies its own signed key record before decrypting the image. The same files are verified on GitHub and CNB. Use the grouped format with a monitor running the grouped OTA reader.

This repository contains release assets and maintenance/synchronization tools. Private application source, user settings, account credentials and signing private keys are not distributed here.

Release only the image matching the exact board profile. Initial manufacturing programming is required before automatic OTA can work.

See [release maintenance](docs/ota-release.md). Firmware supports monitoring and does not send printer heating, motion or print commands.
