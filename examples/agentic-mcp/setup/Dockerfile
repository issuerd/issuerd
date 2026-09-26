FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir httpx==0.28.1 asyncpg==0.31.0

WORKDIR /srv/setup
COPY setup.py verify.py ./

# One-shot post-provision step (see setup.py); verify.py is the opt-in
# end-to-end self-check:  docker compose run --rm --entrypoint python setup verify.py
CMD ["python", "setup.py"]
