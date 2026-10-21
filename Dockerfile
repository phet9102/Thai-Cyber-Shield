# ---------------------------------------------------------------------------
# Thai Cyber Shield - API + Ada engine image (frontend deploys to Vercel)
#   docker build -t thai-cyber-shield-api .
#   docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
#     --pids-limit=256 --memory=512m -p 8000:8000 \
#     -e TCS_ENGINE_SHA256=<printed at build> -e TCS_ALLOWED_ORIGINS=https://<your>.vercel.app \
#     -e TCS_ALLOWED_HOSTS=<api host> -e TCS_TRUSTED_PROXIES=<lb cidr> thai-cyber-shield-api
# ---------------------------------------------------------------------------

# ---- Stage 1: build the Ada engine ----------------------------------------
FROM debian:bookworm-slim AS engine
RUN apt-get update \
 && apt-get install -y --no-install-recommends gnat gprbuild \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY engine/ ./
RUN gprbuild -P tcs_engine.gpr -XBUILD=release -p \
 && strip bin/tcs_engine \
 && sha256sum bin/tcs_engine | tee /src/engine.sha256

# ---- Stage 2: runtime -----------------------------------------------------
FROM python:3.12-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgnat-12 util-linux \
        tesseract-ocr tesseract-ocr-tha tesseract-ocr-eng libzbar0 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin tcs

COPY --from=engine --chown=root:root --chmod=0555 /src/bin/tcs_engine /opt/tcs/bin/tcs_engine
COPY --from=engine /src/engine.sha256 /opt/tcs/engine.sha256

WORKDIR /app
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=root:root --chmod=0555 api/app ./app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TCS_ENV=production \
    TCS_ENGINE_PATH=/opt/tcs/bin/tcs_engine \
    TCS_TESSERACT_PATH=/usr/bin/tesseract \
    OMP_THREAD_LIMIT=1

USER tcs
EXPOSE 8000
# Render/Heroku-style platforms inject $PORT; default 8000 elsewhere
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} \
     --no-server-header --no-proxy-headers --no-date-header \
     --limit-concurrency 256 --timeout-keep-alive 5 \
     --h11-max-incomplete-event-size 16384"]
