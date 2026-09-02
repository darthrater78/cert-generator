FROM python:3.14-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir bcrypt cryptography==50.0.1 flask==3.1.3 waitress

COPY app/ app/

RUN useradd -r -u 1000 -s /bin/false appuser \
    && mkdir -p /data/db /data/exports \
    && chown -R appuser:appuser /data

USER appuser

ENV DB_DIR=/data/db
ENV EXPORT_DIR=/data/exports

EXPOSE 5000

CMD ["python", "-m", "app.serve"]
