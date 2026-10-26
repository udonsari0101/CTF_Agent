# The CI build passes a verified GHCR toolchain digest, never a mutable tag.
ARG TOOLCHAIN_IMAGE
FROM ${TOOLCHAIN_IMAGE}
ARG RELEASE_SHA
ARG LOCAL_INSTALL=false
LABEL org.opencontainers.image.source="https://github.com/udonsari0101/CTF_Agent" \
      org.opencontainers.image.revision=$RELEASE_SHA \
      io.github.ctf-agent.local-install=$LOCAL_INSTALL

COPY --chown=0:0 --chmod=0555 deploy/submit-flag /usr/local/libexec/ctf-command/submit-flag
COPY --chown=0:0 --chmod=0555 deploy/request-remote /usr/local/libexec/ctf-command/request-remote
COPY --chown=0:0 --chmod=0555 deploy/connect-remote /usr/local/libexec/ctf-command/ctf-connect
COPY --chown=0:0 --chmod=0555 deploy/ctf-browser /usr/local/libexec/ctf-command/ctf-browser
RUN ln -s /usr/local/libexec/ctf-command/submit-flag /usr/local/bin/submit-flag \
    && ln -s /usr/local/libexec/ctf-command/request-remote /usr/local/bin/request-remote \
    && ln -s /usr/local/libexec/ctf-command/ctf-connect /usr/local/bin/ctf-connect \
    && ln -s /usr/local/libexec/ctf-command/ctf-browser /usr/local/bin/ctf-browser

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    CTF_DATA_DIR=/data CTF_DB_DIR=/database/sqlite \
    CTF_CONFIG_DIR=/data/config CTF_LOG_DIR=/database/logs \
    CTF_RELEASE_SHA=$RELEASE_SHA \
    HOME=/data/config/home npm_config_cache=/data/runtime/npm-cache \
    SHELL=/usr/local/libexec/ctf-command/bash \
    TZ=Asia/Seoul
WORKDIR /app
COPY ctf_agent ./ctf_agent
COPY --chown=0:0 --chmod=0444 deploy/production-update.py /app/deploy/production-update.py
COPY --chown=0:0 --chmod=0444 .github/scripts/remote-rollout.sh /app/deploy/remote-rollout.sh
USER 10001:10001
EXPOSE 5050
CMD ["python", "-m", "uvicorn", "ctf_agent.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "5050", "--workers", "1", "--no-proxy-headers"]
