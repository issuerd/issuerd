FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN useradd --create-home --uid 10001 chatapp

WORKDIR /srv/chatapp

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app/ ./app/

# DPOP_KEY_PATH defaults to ./data/dpop_key.pem — the key must be writable by
# the non-root user (persisted there so restarts keep the same cnf.jkt).
RUN mkdir -p /srv/chatapp/data && chown -R chatapp:chatapp /srv/chatapp

USER chatapp

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
