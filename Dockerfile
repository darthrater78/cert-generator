FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

RUN useradd -r -u 1000 -s /bin/false appuser \
    && mkdir -p /data/db /data/exports \
    && chown -R appuser:appuser /data

USER appuser

ENV DB_DIR=/data/db
ENV EXPORT_DIR=/data/exports

EXPOSE 5000

CMD ["python", "-m", "app.serve"]
