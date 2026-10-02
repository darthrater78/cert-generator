# Cert Generator Pal, the Windows companion app, built here so the server can offer it
# for download on the LAN (/pal/CertGeneratorPal.exe). Self-contained: the PC needs no .NET.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0.401@sha256:83e0db97c45d2e39b80123fe42940a23c423405a17f80b608a4b8768033d6392 AS pal
WORKDIR /src
COPY pal/ pal/
RUN dotnet publish pal/src/CertGeneratorPal -c Release -o /out \
    && rm -f /out/*.pdb

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
# Read-only and root-owned: the app (appuser) can serve the EXE but never replace it, and the
# server refuses to serve a copy it could write to (app/routes/pal.py).
COPY --from=pal --chown=root:root --chmod=0444 /out/CertGeneratorPal.exe /app/pal/CertGeneratorPal.exe
RUN chmod 0555 /app/pal

RUN useradd -r -u 1000 -s /bin/false appuser \
    && mkdir -p /data/db /data/exports \
    && chown -R appuser:appuser /data

USER appuser

ENV DB_DIR=/data/db
ENV EXPORT_DIR=/data/exports

EXPOSE 5000

CMD ["python", "-m", "app.serve"]
