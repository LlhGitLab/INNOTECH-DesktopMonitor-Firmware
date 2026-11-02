# Signed OTA release tooling

Offline packaging, public build configuration and the real CNB mirror adapter are implemented. Repositories, maintainer signing key and CI configuration are not provisioned. No release or device update has been performed. Device download policy is GitHub first in every region and one CNB fallback.

## Local signing and build configuration

Install `python -m pip install -r tools/ota/requirements.txt`. Supply an existing RSA2048 exponent65537 private PEM from the maintainer's offline signing environment; never place it in source, packages or CI. These tools do not generate production keys. Tests create ephemeral development keys in memory.

Generate a new public-only header from explicitly supplied coordinates and public PEM:

```powershell
python -m tools.ota.configure --public-key public.pem --github-repo OWNER/REPO --cnb-repo ORG/REPO --sequence 7 --version 1.2.3 --profile esp12e --output release_config.generated.h
```

The helper refuses an existing output path, unsafe coordinates and private PEM. It emits OTA_GITHUB_REPO, OTA_CNB_REPO, OTA_PUBLIC_KEY, OTA_SEQUENCE, OTA_VERSION and OTA_PROFILE. Integrate this header through the reviewed firmware build configuration. GitHub coordinates have two path components; CNB may have nested organizations. Coordinates and public PEM are not secrets.

The linked BIN must retain exactly one marker `INNOTECH_OTA_META_V1|seq=7|version=1.2.3|profile=esp12e|` matching its build configuration. Sequence is a positive uint32; version is printable ASCII up to 31 characters. Current BIN maximum is 1,044,464 bytes (ESP12E). Future boards need reviewed per-profile image limits. Magic byte 0xe9 and marker checks are packaging sanity checks, not a full firmware-layout parser.

```powershell
python -m tools.ota.release package --image firmware/.pio/build/esp12e/firmware.bin --output release-v1.2.3 --key X:/offline/private.pem --sequence 7 --version 1.2.3 --profile esp12e --tag v1.2.3 --artifact monitor.bin
python -m tools.ota.release verify --image release-v1.2.3/monitor.bin --manifest release-v1.2.3/manifest-esp12e.json --key public.pem
python -m tools.ota.mirror --package release-v1.2.3 --public-key public.pem --tag v1.2.3
```

Output directory must not exist. Only an explicitly named regular .bin file and its generated manifest are copied. Directory inputs, symlinks, mismatched metadata and oversized images are rejected. Never publish workspace archives, credentials, keys or filesystem images. Publish exactly these verified assets as a stable GitHub release.

Envelope is compact JSON containing exactly payload and signature. Exact UTF-8 payload bytes and raw image each use RSA2048 PKCS1v1.5 SHA256; signatures are lowercase hex512. Payload fields are exactly schema, channel, sequence, version, profile, tag, artifact, size, sha256, image_signature. Maximum envelope 4096 bytes. Duplicates, wrong types/ranges, unsafe components and hash/length/signature mismatch fail closed. Device additionally enforces current sequence and board profile.

## GitHub Actions and real CNB publishing

Create the selected public GitHub/CNB repositories and an existing target commit/branch in CNB. Configure the `ota-mirror` GitHub environment with:

- Repository/environment variables: OTA_PROFILE, OTA_ARTIFACT, OTA_PUBLIC_KEY_PEM (public PEM only), CNB_REPO, CNB_TARGET_COMMITISH and CNB_STORAGE_HOSTS (comma-separated exact storage hostnames, no wildcards). Discover actual CNB presigned upload/download storage hosts from official setup responses; no default wildcard is supplied.
- Protected environment secret CNB_TOKEN with only the required `repo-release:rw` scope.
- OTA_MIRROR_ENABLED=true after reviewing coordinates, host allowlist and environment protection. Until configured the publish command fails closed. No production credentials are supplied by this implementation.

Workflow runs only for published non-draft, non-prerelease releases. It serializes stable mirror jobs, downloads explicit profile/artifact filenames, checks signed tag equals release tag, and verifies downloaded bytes before publishing. It invokes `--publish` only in CI; CLI requires CI=true and OTA_MIRROR_ENABLED=true and reads token only from environment. No token/private key is printed or included in packages.

Mirror first verifies the event tag and exact signed manifest against GitHub's actual `/releases/latest` selection. A published release intentionally not marked Latest cannot advance CNB stable. The anonymous GitHub checker reads release id/tag, downloads `/releases/latest/download/manifest-<profile>.json`, verifies its signature and exact envelope identity, then rereads release identity. It repeats that check after immutable mirroring and immediately before stable upload confirmation; a changed Latest id/tag/manifest aborts promotion. These checks do not depend on event publication order. GH_REPO is supplied by the workflow's github.repository environment value.

Mirror verifies the dedicated package contains exactly two expected files. It checks current signed stable manifest before changes: old sequence or same sequence with different envelope is rejected. It creates/looks up the version release and uploads image plus version manifest with overwrite=false. Existing immutable bytes must match exactly. Each immutable file is anonymously downloaded in full and compared with original bytes before stable promotion. It rechecks stable did not change during upload, then creates/looks up ota-stable and uploads only stable manifest with overwrite=true. Final stable bytes are read back and compared. Repeating identical input does not re-upload assets. Tag ota-stable is reserved.

CI concurrency protects this workflow's writers. GitHub Latest and CNB attachment confirmation are separate services without a shared atomic transaction; a Latest change after the final authority check can still race the confirmation. The implementation minimizes this window with a check immediately before confirmation; future runs detect divergence. CNB's documented API does not provide an atomic compare-and-swap attachment contract; keep this workflow the sole stable-manifest writer. An out-of-band concurrent writer between the final read and overwrite remains a limitation. Failures before promotion leave stable unchanged. Network failure after confirmation may leave a successfully uploaded immutable asset; retry verifies it before reuse.

HTTPS validates certificates using Python default trust. API bearer is restricted to exact api.cnb.cool and the configured repository release path. Authenticated URLs require exact configured origin and canonical repository release paths. Raw controls, backslashes, empty query markers, fragments, dot segments, empty path components, semicolons and all percent encodings are rejected before bearer attachment; encoded and double-encoded traversal cannot normalize outside the repository. Confirmation additionally requires the exact release-id/asset-upload-confirmation prefix followed by nonempty upload-token and asset-path components, with no returned query. Only the tool-generated ttl=0 query is permitted on the final confirmation request. Authenticated requests and PUT uploads never follow redirects. Presigned storage uploads never receive the API bearer. Anonymous downloads allow at most three redirects, restricted to cnb.cool and explicitly allowlisted storage hosts, with HTTPS/port checks, bounded response length, 15-second socket timeout and 90-second monotonic operation deadline checked between chunks/redirects (a blocked read can add up to one socket timeout). Loopback HTTP is available only through a Python constructor test option; the public CLI cannot enable it.

## Official protocol evidence

Retrieved 2026-11-02: [CNB Swagger JSON](https://api.cnb.cool/swagger.json), discovered from apiDescriptionUrl in [official UI](https://api.cnb.cool/) source. Relevant operations/schemas are preserved in tools/ota/cnb-openapi-evidence.json.

- GET /{repo}/-/releases/tags/{tag}: release details/id/assets.
- POST /{repo}/-/releases: create using tag_name, target_commitish, draft=false, prerelease=false, make_latest=false (string).
- POST /{repo}/-/releases/{release_id}/asset-upload-url: asset_name, size, overwrite, ttl=0; response upload_url, verify_url, expires_in_sec.
- PUT raw file to upload_url, explicitly stated in official operation description.
- POST verify_url (official confirmation path), ttl=0: associates uploaded attachment with release.
- GET /{repo}/-/releases/download/{tag}/{filename}: documented 302 to time-limited download location.

The supplied attachments plugin URL returned 404 during initial research, but this is superseded by the complete official Swagger protocol discovery; it is no longer an implementation blocker.

## Validation limits

Scoped tests use synthetic application bytes, in-memory test keys and a 127.0.0.1 fake HTTP CNB service. They exercise full real HTTP adapter flow, bearer separation, ordered byte verification, idempotency, immutable tamper rejection, stable downgrade rejection, redirect/response-size rejection, manifest duplicates/types and public-only configuration. No real repository creation, CNB POST/PUT, GitHub release, live token scope, anonymous production TLS redirect chain, full SDK image or physical device update/rollback was verified. These are setup/live-validation dependencies, not claimed successes.

GitHub authority reference checked 2026-11-02: [official latest-release REST documentation](https://docs.github.com/en/rest/releases/releases#get-the-latest-release); public resources support anonymous reads and application/vnd.github+json. Tests cover non-Latest publication, Latest id/tag or exact manifest change, and changes during immutable/stable upload. Generated-header CLI roundtrip verifies all six firmware macros and public PEM identity; protected publish failure cases verify no secret or traceback appears in stdout/stderr.
