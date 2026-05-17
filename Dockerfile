# swf-node Dockerfile — multi-stage, slim, no system services.
#
# Honest scope: the image is most useful on Linux servers where
# `--network host` lets mDNS multicast reach the LAN. On Docker
# Desktop (macOS / Windows) the host-network mode runs inside a tiny
# VM and does NOT expose host LAN multicast — peers won't discover
# each other automatically. For laptops, prefer `pipx install swf-node`.

# syntax=docker/dockerfile:1.7

# ---- builder: install deps into a target dir we'll copy into runtime
FROM python:3.12-slim AS builder

WORKDIR /build

# Build deps for the rare case a wheel is unavailable on this arch.
# All current swf-node deps ship wheels for amd64 + arm64; this is a
# safety net.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential libssl-dev libffi-dev \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# `--target /install` makes the deps relocatable without needing pip
# in the runtime image.
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --target /install '.[community-full]'

# ---- runtime: minimal layer
FROM python:3.12-slim AS runtime

# Non-root user. UID 1000 matches the typical first user on a
# host-mounted Linux box, so volume permissions Just Work.
RUN useradd --create-home --uid 1000 swf

# Drop the deps in.
COPY --from=builder /install /usr/local/lib/python3.12/site-packages

USER swf
WORKDIR /home/swf

# Default state locations (all overridable via env / volume mounts).
# Note: SWF_BIND defaults to 0.0.0.0 in the container because anything
# inside Docker that wants to be reachable has to bind beyond loopback.
# When run with `--network host`, this is the host's 0.0.0.0.
ENV SWF_CONFIG_DIR=/home/swf/.config/swf \
    SWF_KNOWLEDGE_DIR=/home/swf/world_knowledge \
    SWF_STATE_DIR=/home/swf/.local/share/swf \
    SWF_BIND=0.0.0.0 \
    SWF_PORT=7777

EXPOSE 7777

# Persist state across container rebuilds.
VOLUME ["/home/swf/.config/swf", "/home/swf/world_knowledge", "/home/swf/.local/share/swf"]

# Healthcheck pings /health. The 5s interval is a guess; adjust per
# orchestrator. Returns 1 within ~3s if the daemon isn't responding.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7777/health', timeout=2).read()" \
        || exit 1

# `python -m swf` dispatches to `swf.peer_server.main`, same as the
# `swf-node` console script. We use the module form so the image
# doesn't depend on a specific bin location.
ENTRYPOINT ["python", "-m", "swf"]
