FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
