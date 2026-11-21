FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd

ENV PYTHONUNBUFFERED=1

WORKDIR /srv/setup
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY setup.py verify.py ./

# One-shot post-provision step (see setup.py); verify.py is the opt-in
# end-to-end self-check:  docker compose run --rm --entrypoint python setup verify.py
CMD ["python", "setup.py"]
