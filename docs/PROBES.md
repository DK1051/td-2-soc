# Probes — td-2-soc

### 2026-10-22 (T2-S01)

## Probe 2026-10-22T09:52Z
- arch: x86_64
- cpus: 4  memory: 15 GB
- avx2 flags: 4
- python: Python 3.13.16
- java: Picked up JAVA_TOOL_OPTIONS: [proxy settings removed before commit — they list internal proxy hosts]
- docker:   not available
- pwsh: 7.6.7
- keycloak: /opt/keycloak Keycloak 26.8.1
- reach https://repo1.maven.org/maven2/ -> HTTP 429
- reach https://mcr.microsoft.com/v2/ -> HTTP 200
- reach https://packages.microsoft.com/ -> HTTP 200
- reach https://pypi.org/simple/ -> HTTP 200
- reach https://www.powershellgallery.com/ -> HTTP 000
- reach https://graph.microsoft.com/v1.0/ -> HTTP 000
- reach https://management.azure.com/ -> HTTP 000

Notes on this run (added by the director, not by `probe.sh`): the `java:` line's proxy host list was removed before commit (it names internal hosts); `docker:` and `keycloak:` each printed over two lines and are joined here. This probe ran in one cloud session shared with the hub and the other three tracks (Eojin's D0 launch), so `pwsh` and `keycloak` come from the Track 1 and Track 3 setup scripts, not from this track's environment.

What each result means for Track 2:
- `arch: x86_64` — standard 64-bit Intel/AMD processor; the Kusto emulator (Microsoft's local copy of the Azure Data Explorer query engine) is built only for this type, so this is good.
- `cpus: 4  memory: 15 GB` — 4 cores and about 15 GB of memory; TODO(verify) against the emulator's documented minimum.
- `avx2 flags: 4` — every core has AVX2, the fast maths instructions the emulator needs; good.
- `python: Python 3.13.16` — newer than the 3.12 this repo targets; the generator uses only the standard library.
- `java:` — Java 21 is installed; Track 2 does not use it.
- `docker: not available` — the Docker program exists but no Docker engine is running, so the emulator container cannot start in this session. This is the blocker for running KQL locally.
- `pwsh: 7.6.7` — PowerShell is present (installed by Track 3's setup); Track 2 does not need it.
- `keycloak: … 26.8.1` — installed by the Track 1/3 setup; Track 2 does not need it.
- `reach https://repo1.maven.org/maven2/ -> HTTP 429` — Maven Central said "too many requests"; not used by Track 2.
- `reach https://mcr.microsoft.com/v2/ -> HTTP 200` — Microsoft's container registry, where the emulator image lives, is reachable; the image could be pulled if a Docker engine were running.
- `reach https://packages.microsoft.com/ -> HTTP 200` — Microsoft's Linux package site is reachable; not needed here.
- `reach https://pypi.org/simple/ -> HTTP 200` — the Python package index is reachable, so `pip install -r requirements.txt` can work.
- `reach https://www.powershellgallery.com/ -> HTTP 000` — blocked, as expected; not needed here.
- `reach https://graph.microsoft.com/v1.0/ -> HTTP 000` — blocked, as expected and as the safety rules require.
- `reach https://management.azure.com/ -> HTTP 000` — blocked, as expected; no Azure access from a cloud session.

Decision (step 2 rule): `arch` is `x86_64` and `avx2 flags` is 4, but docker is `not available`, so T2-S02 is **AT RISK**: it falls back to data tests in the `kql` CI job (GitHub runners are x86-64 with Docker). The background image pull did not run: `/tmp/kusto-pull.log` does not exist, because this session's start hook belongs to the hub repo, not to `td-2-soc`.

### 2026-10-22 (T2-S02) — Docker engine and emulator
- The probe's `docker: not available` meant the Docker *engine* was not running, not that Docker is missing. Started by hand with `dockerd` (this session runs as root): `Server Version: 29.9.1`, storage driver overlayfs.
- Emulator image pinned by digest: `mcr.microsoft.com/azuredataexplorer/kustainer-linux@sha256:7479dc8efa4b3c15bc1a245b418464e88b5328cf6e4781881d73fe4f79d03eb1`. Read from Microsoft's registry (`Docker-Content-Digest` header for `latest` on 2026-10-22) and matched by `docker image inspect` after the pull.
- The emulator ran in the session on host port 9000 (`.show cluster` → 200), so T2-S02 took the emulator path, not the fallback.
