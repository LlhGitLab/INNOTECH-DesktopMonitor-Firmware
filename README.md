# INNOTECH Desktop Monitor Firmware

Signed firmware distribution for INNOTECH desktop printer monitors.

- Primary releases: https://github.com/LlhGitLab/INNOTECH-DesktopMonitor-Firmware/releases
- CNB mirror: https://cnb.cool/INNOTECH8/INNOTECH-DesktopMonitor-Firmware/-/releases
- Device policy: GitHub first, CNB fallback after bounded failure or sustained slow transfer.
- Verification public key: [keys/ota-public.pem](keys/ota-public.pem).

This repository contains release assets and maintenance/synchronization tools. Private application source, user settings, account credentials and signing private keys are not distributed here.

Release only the image matching the exact board profile. Initial manufacturing programming is required before automatic OTA can work.

See [release maintenance](docs/ota-release.md). Firmware supports monitoring and does not send printer heating, motion or print commands.
