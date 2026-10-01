FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

# Debian security fixes land before the pinned base image is rebuilt upstream.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# pip is only needed to install; removing it drops its vendored libraries
# (urllib3, msgpack, ...) and their advisories from the runtime image.
RUN pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y pip

COPY app/ app/

RUN useradd -r -u 1000 -s /bin/false appuser \
    && mkdir -p /data/db /data/exports \
    && chown -R appuser:appuser /data

USER appuser

ENV DB_DIR=/data/db
ENV EXPORT_DIR=/data/exports

EXPOSE 5000

CMD ["python", "-m", "app.serve"]
