FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

ENV PYTHONUNBUFFERED=1

WORKDIR /srv/setup
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY setup.py verify.py ./

# One-shot post-provision step (see setup.py); verify.py is the opt-in
# end-to-end self-check:  docker compose run --rm --entrypoint python setup verify.py
CMD ["python", "setup.py"]
