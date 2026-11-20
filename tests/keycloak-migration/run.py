#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

"""Reproducible Keycloak migration acceptance with sanitized evidence."""

import argparse
import base64
import copy
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REALM = "migration-lab"
CLIENT_ID = "migration-check"
PUBLIC_CLIENT_ID = "migration-public"
KEYCLOAK_VERSION = "26.7.1"
KEYCLOAK_IMAGE = f"quay.io/keycloak/keycloak:{KEYCLOAK_VERSION}"
POSTGRES_IMAGE = "postgres:16.10-alpine"
ALGORITHMS = ("argon2id", "pbkdf2-sha256", "pbkdf2-sha512")


class Failure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def b64(value):
    return base64.b64encode(value).decode().rstrip("=")


def b64url(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def now_label():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_private(path, document):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")


def mapper(name, mapper_type, extra=None):
    config = {
        "access.token.claim": "true",
        "id.token.claim": "true",
        "userinfo.token.claim": "true",
    }
    config.update(extra or {})
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": mapper_type,
        "config": config,
    }


def default_mappers():
    return [
        mapper("department", "oidc-usermodel-attribute-mapper", {
            "user.attribute": "department", "claim.name": "dept", "jsonType.label": "String",
        }),
        mapper("first name", "oidc-usermodel-property-mapper", {
            "user.property": "firstName", "claim.name": "given_name_custom",
        }),
        mapper("full name", "oidc-full-name-mapper"),
        mapper("address", "oidc-address-mapper"),
        mapper("groups", "oidc-group-membership-mapper", {
            "claim.name": "groups", "full.path": "false",
        }),
        mapper("realm roles", "oidc-usermodel-realm-role-mapper"),
        mapper("client roles", "oidc-usermodel-client-role-mapper", {
            "usermodel.clientRoleMapping.clientId": CLIENT_ID,
        }),
        mapper("audience", "oidc-audience-mapper", {
            "included.custom.audience": "migration-extra-audience",
        }),
        mapper("origins", "oidc-allowed-origins-mapper"),
    ]


def role_resources():
    return {
        "groups": [{
            "name": "developers",
            "path": "/developers",
            "realmRoles": ["group-realm-role"],
            "clientRoles": {CLIENT_ID: ["group-client-role"]},
        }],
        "roles": {
            "realm": [
                {"name": "migration-realm-role"},
                {"name": "group-realm-role"},
                {
                    "name": "migration-realm-composite",
                    "composite": True,
                    "composites": {"realm": ["migration-realm-role"]},
                },
            ],
            "client": {CLIENT_ID: [
                {"name": "migration-client-role"},
                {"name": "group-client-role"},
                {
                    "name": "migration-client-composite",
                    "composite": True,
                    "composites": {"client": {CLIENT_ID: ["migration-client-role"]}},
                },
            ]},
        },
        "clientScopes": [
            {
                "name": "migration-default",
                "protocol": "openid-connect",
                "protocolMappers": default_mappers(),
            },
            {
                "name": "migration-optional",
                "protocol": "openid-connect",
                "protocolMappers": [mapper("optional", "oidc-usermodel-attribute-mapper", {
                    "user.attribute": "optionalnote", "claim.name": "optional_claim",
                })],
            },
        ],
        "scopeMappings": [
            {"client": CLIENT_ID, "roles": ["migration-realm-role", "group-realm-role"]},
            {"clientScope": "migration-default", "roles": ["migration-realm-role", "group-realm-role"]},
            {"clientScope": "migration-optional", "roles": ["migration-realm-role", "group-realm-role"]},
        ],
        "clientScopeMappings": {
            CLIENT_ID: [
                {"client": CLIENT_ID, "roles": ["migration-client-role", "group-client-role"]},
                {"clientScope": "migration-default", "roles": ["migration-client-role", "group-client-role"]},
                {"clientScope": "migration-optional", "roles": ["migration-client-role", "group-client-role"]},
            ],
        },
    }


def user_representation(username, password, credential=None, enabled=True):
    result = {
        "username": username,
        "enabled": enabled,
        "email": f"{username}@example.com",
        "emailVerified": True,
        "firstName": "Alice",
        "lastName": "Migration",
        "attributes": {
            "department": ["engineering"],
            "optionalnote": ["optional-value"],
            "address_locality": ["Tartu"],
            "address_street": ["Migration Street 1"],
        },
        "requiredActions": [],
        "credentials": [] if credential is None else [credential],
    }
    if username == "alice-argon2id":
        result.update({
            "realmRoles": ["migration-realm-composite"],
            "clientRoles": {CLIENT_ID: ["migration-client-composite"]},
            "groups": ["/developers"],
        })
    return result


def make_manifest(user_specs, provenance, claim_checks):
    return {
        "schema_version": 1,
        "keycloak_version": KEYCLOAK_VERSION,
        "realm": REALM,
        "provenance": provenance,
        "users": user_specs,
        "client_scopes": [
            {"name": "migration-default", "assignment": "default", "mapper_count": 9},
            {"name": "migration-optional", "assignment": "optional", "mapper_count": 1},
        ],
        "claim_checks": claim_checks,
        "negative_users": ["disabled-user", "no-password", "history-only"],
    }


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = pathlib.Path(__file__).resolve().parents[2]
        self.temp = tempfile.TemporaryDirectory(prefix="issuerd-keycloak-migration-")
        self.work = pathlib.Path(self.temp.name)
        os.chmod(self.work, 0o700)
        timestamp = f"{now_label()}-{args.backend}-{os.getpid()}"
        self.evidence = args.evidence_dir or self.root / "tests" / "keycloak-migration" / "results" / timestamp
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.redactions = {}
        self.report = {
            "schema_version": 1,
            "status": "FAIL",
            "source": {},
            "target": {"backend": args.backend},
            "credential_families": list(ALGORITHMS),
            "users": [],
            "negative_cases": [],
        }
        self.target_process = None
        self.target_config = self.work / "issuerd.toml"
        self.target_log = self.work / "issuerd.log"
        self.target_port = None
        self.target_admin = secrets.token_urlsafe(32)
        self.target_client_secret = secrets.token_urlsafe(32)
        self.add_secret(self.target_admin, "TARGET_ADMIN_PASSWORD")
        self.add_secret(self.target_client_secret, "TARGET_CLIENT_SECRET")
        self.compose_project = None
        self.fixture = None
        self.manifest = None
        self.secrets = None
        self.target_token = None
        self.source_token = None

    def add_secret(self, value, label):
        if isinstance(value, bytes):
            for encoded in {b64(value), base64.b64encode(value).decode(), value.hex()}:
                if encoded:
                    self.redactions[encoded] = f"<{label}>"
        elif value:
            self.redactions[str(value)] = f"<{label}>"

    def sanitize(self, value):
        if not isinstance(value, str):
            value = str(value)
        for secret, label in sorted(self.redactions.items(), key=lambda item: len(item[0]), reverse=True):
            value = value.replace(secret, label)
        value = re.sub(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "<JWT>", value)
        return value

    def run_command(self, command, secret_output=False, env=None, timeout=300):
        result = subprocess.run(
            command,
            cwd=self.root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            output = result.stdout + result.stderr
            detail = "<redacted command output>" if secret_output else self.sanitize(output.decode(errors="replace")[-8000:])
            raise Failure(f"command failed ({command[0]}): {detail}")
        return result.stdout

    def http(self, method, url, body=None, form=None, token=None, cookie=None, expected=(200,)):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                status = response.status
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as error:
            raw = error.read()
            status = error.code
            response_headers = dict(error.headers.items())
        except urllib.error.URLError as error:
            raise Failure(f"HTTP {method} {url} failed: {error.reason}")
        except ConnectionError as error:
            raise Failure(f"HTTP {method} {url} failed: {error}")
        try:
            document = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            document = None
        if status not in expected:
            safe = self.sanitize(raw.decode(errors="replace")[:2000])
            raise Failure(f"HTTP {method} {url} returned {status}, expected {expected}: {safe}")
        return status, document, response_headers

    def target_url(self, path):
        return f"http://127.0.0.1:{self.target_port}{path}"

    def build_target(self):
        if self.args.issuerd_bin:
            binary = pathlib.Path(self.args.issuerd_bin).resolve()
        else:
            binary = self.root / "target" / "debug" / "issuerd"
            self.run_command(["cargo", "build", "--bin", "issuerd"], timeout=1200)
        if not binary.is_file():
            raise Failure(f"Issuerd binary not found: {binary}")
        return binary

    def target_config_text(self, second=False):
        port = self.second_port if second else self.target_port
        config = (
            f'bind = {json.dumps("0.0.0.0" if second else "127.0.0.1")}\n'
            f'port = {port}\n'
            f'issuer_url = "http://127.0.0.1:{self.target_port}"\n'
        )
        if self.args.backend == "postgres-redis":
            config += f'redis = {json.dumps(self.target_redis_url)}\n'
        if self.args.backend in ("postgres", "postgres-redis"):
            config += f'provision = {json.dumps(str(self.work / "provision.yaml"))}\n'
        config += '[logging]\nformat = "json"\nlevel = "info"\n'
        if self.args.backend == "json-file":
            path = self.work / "target.json"
            config += f'[storage.json_file]\npath = {json.dumps(str(path))}\n'
        elif self.args.backend == "sqlite":
            path = self.work / "target.sqlite"
            config += f'[storage.sqlite]\npath = {json.dumps(str(path))}\n'
        elif self.args.backend in ("postgres", "postgres-redis"):
            config += f'[storage.postgres]\nurl = {json.dumps(self.target_database_url)}\n'
            if self.args.backend == "postgres-redis":
                config += '[cluster]\nenabled = true\n'
        return config

    def start_target(self):
        self.target_port = self.target_port or free_port()
        self.target_config.write_text(self.target_config_text(), encoding="utf-8")
        os.chmod(self.target_config, 0o600)
        env = os.environ.copy()
        env["ISSUERD_BOOTSTRAP_ADMIN_PASSWORD"] = self.target_admin
        log = open(self.target_log, "ab")
        binary = self.build_target()
        self.target_process = subprocess.Popen(
            [str(binary), "daemon", "-c", str(self.target_config)],
            cwd=self.root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        log.close()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if self.target_process.poll() is not None:
                raise Failure("Issuerd target exited before becoming ready")
            try:
                self.http("GET", self.target_url("/ready"), expected=(200,))
                break
            except Failure:
                time.sleep(0.25)
        else:
            raise Failure("Issuerd target did not become ready in 90 seconds")
        if self.args.backend in ("postgres", "postgres-redis"):
            users = self.run_command([
                "docker", "compose", "-p", self.compose_project,
                "-f", str(self.work / "compose.yaml"),
                "exec", "-T", "postgres", "psql", "-U", self.target_psql_user,
                "-d", "issuerd_target", "-At", "-c", "SELECT username FROM users",
            ], secret_output=True).decode().splitlines()
            if "admin" not in users:
                raise Failure("PostgreSQL provisioning did not create the master admin user")
        _, body, _ = self.http(
            "POST",
            self.target_url("/api/v1/auth/admin-token"),
            body={"realm": "master", "username": "admin", "password": self.target_admin},
        )
        self.target_token = body["access_token"]
        self.add_secret(self.target_token, "TARGET_ADMIN_TOKEN")

    def acquire_target_lock(self):
        if getattr(self, "target_lock", None) is not None:
            return
        import fcntl

        lock_path = self.evidence.parent / "target-process.lock"
        self.target_lock = open(lock_path, "a+")
        fcntl.flock(self.target_lock.fileno(), fcntl.LOCK_EX)

    def release_target_lock(self):
        if getattr(self, "target_lock", None) is not None:
            self.target_lock.close()
            self.target_lock = None

    def stop_target(self):
        stop_second_target(self)
        if self.target_process is None:
            return
        if self.target_process.poll() is None:
            self.target_process.send_signal(signal.SIGTERM)
            try:
                self.target_process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.target_process.kill()
                self.target_process.wait(timeout=10)
        self.target_process = None

    def admin(self, method, path, body=None, expected=(200,)):
        return self.http(
            method,
            self.target_url(path),
            body=body,
            token=self.target_token,
            expected=expected,
        )

    def password_grant(self, username, password, scope="openid migration-default", source=False, second=False):
        base = self.source_base if source else self.target_url("")
        if second:
            base = getattr(self, "second_base_url", f"http://127.0.0.1:{self.second_port}/")
        base = base.rstrip("/") + "/"
        token = self.source_token if source else self.target_client_secret
        status, body, _ = self.http(
            "POST",
            f"{base}realms/{REALM}/protocol/openid-connect/token",
            form={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "client_secret": token,
                "username": username,
                "password": password,
                "scope": scope,
            },
            expected=(200, 400, 401),
        )
        if isinstance(body, dict) and body.get("access_token"):
            self.add_secret(body["access_token"], "ACCESS_TOKEN")
        if isinstance(body, dict) and body.get("refresh_token"):
            self.add_secret(body["refresh_token"], "REFRESH_TOKEN")
        if isinstance(body, dict) and body.get("id_token"):
            self.add_secret(body["id_token"], "ID_TOKEN")
        return status, body

    def userinfo(self, access_token, source=False):
        base = (self.source_base if source else self.target_url("")).rstrip("/") + "/"
        _, body, _ = self.http(
            "GET",
            f"{base}realms/{REALM}/protocol/openid-connect/userinfo",
            token=access_token,
        )
        return body

    def argon2_hash(self, password, salt):
        process = subprocess.run(
            ["cargo", "run", "--quiet", "--example", "keycloak_migration_hash"],
            cwd=self.root,
            input=json.dumps({"password": password, "salt": b64(salt)}).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1200,
            check=False,
        )
        if process.returncode != 0:
            raise Failure(self.sanitize(process.stderr.decode(errors="replace")[-4000:]))
        return process.stdout.decode()

    def generate_fixture(self):
        specifications = [
            ("alice-argon2id", "argon2id", 5),
            ("bob-p256-current", "pbkdf2-sha256", 600_000),
            ("carol-p512-current", "pbkdf2-sha512", 210_000),
            ("dave-p256-legacy", "pbkdf2-sha256", 27_500),
            ("erin-p512-legacy", "pbkdf2-sha512", 27_500),
        ]
        users = []
        user_specs = []
        secret_users = {}
        for username, algorithm, iterations in specifications:
            password = secrets.token_urlsafe(24)
            salt = secrets.token_bytes(16)
            secret_users[username] = password
            self.add_secret(password, f"PASSWORD_{username.upper()}")
            self.add_secret(salt, f"SALT_{username.upper()}")
            if algorithm == "argon2id":
                phc = self.argon2_hash(password, salt)
                self.add_secret(phc, f"HASH_{username.upper()}")
                credential = {"type": "password", "secretData": phc}
                parameters = {"t": iterations, "m": 7168, "p": 1, "hash_length": 32}
            else:
                digest_name = algorithm.removeprefix("pbkdf2-").replace("-", "")
                digest = hashlib.pbkdf2_hmac(digest_name, password.encode(), salt, iterations)
                self.add_secret(digest, f"HASH_{username.upper()}")
                credential = {
                    "type": "password",
                    "credentialData": {"algorithm": algorithm, "hashIterations": iterations},
                    "secretData": {"value": base64.b64encode(digest).decode(), "salt": base64.b64encode(salt).decode()},
                }
                parameters = {"iterations": iterations}
            users.append(user_representation(username, password, credential))
            user_specs.append({
                "username": username,
                "algorithm": algorithm,
                "enabled": True,
                "parameters": parameters,
            })
        disabled_password = secrets.token_urlsafe(24)
        secret_users["disabled-user"] = disabled_password
        self.add_secret(disabled_password, "PASSWORD_DISABLED_USER")
        disabled_salt = secrets.token_bytes(16)
        disabled_hash = hashlib.pbkdf2_hmac("sha256", disabled_password.encode(), disabled_salt, 27_500)
        disabled_credential = {
            "type": "password",
            "credentialData": {"algorithm": "pbkdf2-sha256", "hashIterations": 27_500},
            "secretData": {"value": base64.b64encode(disabled_hash).decode(), "salt": base64.b64encode(disabled_salt).decode()},
        }
        users.append(user_representation("disabled-user", disabled_password, disabled_credential, enabled=False))
        users.append(user_representation("no-password", None))
        history_salt = secrets.token_bytes(16)
        history_password = secrets.token_urlsafe(24)
        history_hash = hashlib.pbkdf2_hmac("sha256", history_password.encode(), history_salt, 27_500)
        history_credential = {
            "type": "password-history",
            "credentialData": {"algorithm": "pbkdf2-sha256", "hashIterations": 27_500},
            "secretData": {"value": base64.b64encode(history_hash).decode(), "salt": base64.b64encode(history_salt).decode()},
        }
        users.append(user_representation("history-only", history_password, history_credential))
        self.add_secret(history_password, "PASSWORD_HISTORY_ONLY")
        document = {
            "realm": REALM,
            "users": users,
            "clients": [{
                "clientId": CLIENT_ID,
                "publicClient": False,
                "fullScopeAllowed": False,
                "redirectUris": ["http://localhost:8080/cb"],
                "webOrigins": ["http://localhost:8080"],
                "defaultClientScopes": ["migration-default"],
                "optionalClientScopes": ["migration-optional"],
            }, {
                "clientId": PUBLIC_CLIENT_ID,
                "publicClient": True,
                "fullScopeAllowed": False,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": True,
                "redirectUris": ["http://localhost:8080/public-cb"],
                "webOrigins": ["http://localhost:8080"],
                "defaultClientScopes": ["migration-default"],
                "optionalClientScopes": ["migration-optional"],
            }],
            **role_resources(),
        }
        claim_checks = [{
            "username": "alice-argon2id",
            "scope": "openid migration-default",
            "expect": {
                "dept": "engineering",
                "given_name_custom": "Alice",
                "name": "Alice Migration",
                "address": {"locality": "Tartu", "street_address": "Migration Street 1"},
                "groups": ["developers"],
                "realm_access": {"roles": ["migration-realm-role", "group-realm-role"]},
                "resource_access": {CLIENT_ID: {"roles": ["migration-client-role", "group-client-role"]}},
                "aud": ["migration-extra-audience"],
                "allowed_origins": ["http://localhost:8080"],
            },
            "forbid": ["optional_claim"],
        }, {
            "username": "alice-argon2id",
            "scope": "openid migration-default migration-optional",
            "expect": {"optional_claim": "optional-value"},
            "forbid": [],
        }]
        manifest = make_manifest(user_specs, "synthetic-compatible fixture; not Keycloak-produced", claim_checks)
        secret_input = {
            "users": secret_users,
            "client_secret": secrets.token_urlsafe(32),
        }
        self.add_secret(secret_input["client_secret"], "SOURCE_CLIENT_SECRET")
        return document, manifest, secret_input

    def prepare_fixture(self):
        if self.args.fixture:
            raw = pathlib.Path(self.args.fixture).read_bytes()
            self.fixture = json.loads(raw)
            manifest_path = self.args.manifest or pathlib.Path(self.args.fixture).with_name("fixture-manifest.json")
            secrets_path = self.args.secrets or pathlib.Path(self.args.fixture).with_name("fixture-secrets.json")
            self.manifest = load_json(manifest_path)
            self.secrets = load_json(secrets_path)
        elif self.args.synthetic:
            self.fixture, self.manifest, self.secrets = self.generate_fixture()
            raw = json.dumps(self.fixture, separators=(",", ":"), sort_keys=True).encode()
        else:
            raw = generate_keycloak_fixture(self)
        write_private(self.work / "realm-export.json", self.fixture)
        write_private(self.work / "fixture-manifest.json", self.manifest)
        write_private(self.work / "fixture-secrets.json", self.secrets)
        self.report["source"].update({
            "keycloak_version": self.manifest.get("keycloak_version"),
            "provenance": self.manifest.get("provenance"),
            "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        })
        for password in self.secrets.get("users", {}).values():
            self.add_secret(password, "FIXTURE_USER_PASSWORD")
        self.add_secret(self.secrets.get("client_secret"), "SOURCE_CLIENT_SECRET")
        for client in self.fixture.get("clients", []):
            if client.get("clientId") == CLIENT_ID or client.get("client_id") == CLIENT_ID:
                client["secret"] = self.target_client_secret

    def create_target_realm(self):
        self.admin("POST", "/admin/realms", body={"realm": REALM, "enabled": True}, expected=(201,))
        _, result, _ = self.admin(
            "POST",
            f"/admin/realms/{REALM}/partialImport?ifResourceExists=OVERWRITE",
            body=self.fixture,
        )
        self.report["target"]["import_summary"] = {
            "added": result.get("added"),
            "skipped": result.get("skipped"),
            "updated": result.get("updated"),
        }

    def verify_inventory(self):
        _, users, _ = self.admin("GET", f"/admin/realms/{REALM}/users?max=1000")
        _, scopes, _ = self.admin("GET", f"/admin/realms/{REALM}/client-scopes?max=1000")
        _, clients, _ = self.admin("GET", f"/admin/realms/{REALM}/clients?max=1000")
        expected_users = {user["username"] for user in self.fixture.get("users", [])}
        actual_users = {user["username"] for user in users}
        missing = expected_users - actual_users
        if missing:
            raise Failure(f"imported users missing: {sorted(missing)}")
        expected_mappers = {
            "migration-default": 9,
            "migration-optional": 1,
        }
        for name, expected_count in expected_mappers.items():
            scope = next((scope for scope in scopes if scope.get("name") == name), None)
            if scope is None:
                raise Failure(f"imported client scope missing: {name}")
            _, detail, _ = self.admin("GET", f"/admin/realms/{REALM}/client-scopes/{scope['id']}")
            mappers = detail.get("protocol_mappers") or detail.get("protocolMappers") or []
            if len(mappers) != expected_count:
                raise Failure(f"protocol mapper count mismatch for {name}: {len(mappers)} != {expected_count}")
            if name == "migration-default":
                expected_types = {
                    "oidc-usermodel-attribute-mapper",
                    "oidc-usermodel-property-mapper",
                    "oidc-full-name-mapper",
                    "oidc-address-mapper",
                    "oidc-group-membership-mapper",
                    "oidc-usermodel-realm-role-mapper",
                    "oidc-usermodel-client-role-mapper",
                    "oidc-audience-mapper",
                    "oidc-allowed-origins-mapper",
                }
                actual_types = {mapper.get("protocol_mapper") or mapper.get("protocolMapper") for mapper in mappers}
                if actual_types != expected_types:
                    raise Failure("imported protocol mapper types are incomplete")
        client = next((client for client in clients if client.get("client_id") == CLIENT_ID or client.get("clientId") == CLIENT_ID), None)
        if client is None:
            raise Failure(f"imported client missing: {CLIENT_ID}")
        public_client = next(
            (candidate for candidate in clients
             if candidate.get("client_id") == PUBLIC_CLIENT_ID
             or candidate.get("clientId") == PUBLIC_CLIENT_ID),
            None,
        )
        if public_client is None:
            raise Failure(f"imported public client missing: {PUBLIC_CLIENT_ID}")
        if client.get("public_client", client.get("publicClient")) is not False:
            raise Failure("confidential migration client became public")
        if public_client.get("public_client", public_client.get("publicClient")) is not True:
            raise Failure("public migration client lost its public-client flag")
        self.report["target"]["inventory"] = {
            "users": len(expected_users),
            "client_scopes": len([scope for scope in scopes if scope.get("name", "").startswith("migration-")]),
            "clients_present": True,
            "public_client_present": True,
            "protocol_mappers": "PASS",
            "role_and_group_assignments": "PASS",
            "scope_assignments": {
                "default": client.get("default_scopes") or client.get("defaultClientScopes"),
                "optional": client.get("optional_scopes") or client.get("optionalClientScopes"),
            },
        }
        return users

    def verify_claims(self, actual, expected, context):
        for key, value in expected.items():
            if key in ("realm_access", "resource_access", "aud", "groups"):
                continue
            if actual.get(key) != value:
                raise Failure(
                    f"claim mismatch for {context}: {key}; "
                    f"actual={actual.get(key)!r}, expected={value!r}"
                )
        for role in expected.get("realm_access", {}).get("roles", []):
            if role not in actual.get("realm_access", {}).get("roles", []):
                raise Failure(f"missing realm role claim for {context}: {role}")
        for client, mapping in expected.get("resource_access", {}).items():
            for role in mapping.get("roles", []):
                if role not in actual.get("resource_access", {}).get(client, {}).get("roles", []):
                    raise Failure(f"missing client role claim for {context}: {client}/{role}")
        for group in expected.get("groups", []):
            if group not in actual.get("groups", []):
                raise Failure(f"missing group claim for {context}: {group}")
        for audience in expected.get("aud", []):
            actual_audience = actual.get("aud", [])
            if isinstance(actual_audience, str):
                actual_audience = [actual_audience]
            if audience not in actual_audience:
                raise Failure(f"missing audience claim for {context}: {audience}")

    def verify_non_member(self, source=False):
        username = "bob-p256-current"
        if source:
            spec = next(spec for spec in self.manifest["users"] if spec["username"] == username)
            source_policy_for_spec(self, spec)
        status, token = self.password_grant(
            username,
            self.secrets["users"][username],
            source=source,
        )
        if status != 200:
            raise Failure("non-member control login failed")
        claims = self.userinfo(token["access_token"], source=source)
        if "developers" in claims.get("groups", []):
            raise Failure("non-member control unexpectedly received the developers group")
        section = "source" if source else "target"
        self.report[section]["non_member_group_control"] = "PASS"

    def browser_pkce(self, username, password):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        query = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:8080/cb",
            "scope": "openid",
            "state": "migration-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        request = urllib.request.Request(
            self.target_url(f"/realms/{REALM}/protocol/openid-connect/auth?{query}"),
            method="GET",
        )
        opener = urllib.request.build_opener(NoRedirect())
        try:
            with opener.open(request, timeout=30) as response:
                location = response.headers.get("Location")
        except urllib.error.HTTPError as error:
            if error.code not in (302, 303):
                raise
            location = error.headers.get("Location")
        execution_id = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("execution_id", [None])[0]
        if not execution_id:
            raise Failure("browser flow did not return execution_id")
        _, login, _ = self.http(
            "POST",
            self.target_url(f"/api/v1/auth/login?realm={REALM}"),
            body={"execution_id": execution_id, "username": username, "password": password},
            cookie=f"issuerd_flow_{execution_id}=1",
        )
        status, token, _ = self.http(
            "POST",
            self.target_url(f"/realms/{REALM}/protocol/openid-connect/token"),
            form={
                "grant_type": "authorization_code",
                "code": login["code"],
                "redirect_uri": "http://localhost:8080/cb",
                "client_id": CLIENT_ID,
                "client_secret": self.target_client_secret,
                "code_verifier": verifier,
            },
            expected=(200, 400, 401),
        )
        if status != 200:
            raise Failure(f"browser PKCE token exchange failed for {username}")
        if token.get("access_token"):
            self.add_secret(token["access_token"], "ACCESS_TOKEN")

    def verify_logins_and_claims(self, restart=False):
        passwords = self.secrets["users"]
        for spec in self.manifest["users"]:
            username = spec["username"]
            if not spec.get("enabled", True):
                continue
            status, token = self.password_grant(username, passwords[username])
            if status != 200:
                raise Failure(f"post-import login failed for {username}")
            wrong_status, _ = self.password_grant(username, secrets.token_urlsafe(24))
            if wrong_status not in (400, 401):
                raise Failure(f"wrong password was accepted for {username}")
            result = {
                "username": username,
                "algorithm": spec["algorithm"],
                "parameters": spec.get("parameters", {}),
                "post_import_login": "PASS",
                "wrong_password_rejected": True,
                "password_reset_required": False,
            }
            for evidence_key in ("source_login", "oracle"):
                if evidence_key in spec:
                    result[evidence_key] = spec[evidence_key]
            if restart:
                result["restart_login"] = "PASS"
            self.report["users"].append(result)
        for username in self.manifest.get("negative_users", ["disabled-user", "no-password", "history-only"]):
            password = passwords.get(username) or secrets.token_urlsafe(24)
            status, _ = self.password_grant(username, password)
            if status not in (400, 401):
                raise Failure(f"negative user was able to authenticate: {username}")
            self.report["negative_cases"].append({"case": username, "result": "PASS"})
        for check in self.manifest.get("claim_checks", []):
            username = check["username"]
            status, token = self.password_grant(username, passwords[username], check["scope"])
            if status != 200:
                raise Failure(f"claim-check login failed for {username}")
            claims = self.userinfo(token["access_token"])
            self.verify_claims(claims, check.get("expect", {}), username)
            for forbidden in check.get("forbid", []):
                if forbidden in claims:
                    raise Failure(f"unexpected optional claim for {username}: {forbidden}")
        self.verify_non_member()
        if not restart:
            self.browser_pkce("alice-argon2id", passwords["alice-argon2id"])
            self.browser_pkce("bob-p256-current", passwords["bob-p256-current"])
        self.report["target"]["semantic_claims"] = "PASS"

    def normalized_expected_credentials(self):
        expected = {}
        for spec in self.manifest["users"]:
            username = spec["username"]
            user = next(user for user in self.fixture["users"] if user["username"] == username)
            credential = next(
                credential
                for credential in user.get("credentials", [])
                if credential.get("type") == "password"
            )
            secret = credential.get("secretData", credential.get("secret_data"))
            if isinstance(secret, str) and secret.startswith("$"):
                expected[username] = secret
                continue
            if isinstance(secret, str):
                secret = json.loads(secret)
            data = credential.get("credentialData", credential.get("credential_data"))
            if isinstance(data, str):
                data = json.loads(data)
            salt = base64.b64decode("".join(secret["salt"].split()))
            digest = base64.b64decode("".join(secret["value"].split()))
            iterations = data["hashIterations"]
            if spec["algorithm"] == "argon2id":
                algorithm_data = data.get("algorithmData", data.get("additionalParameters", {}))

                def parameter(name, default):
                    value = algorithm_data.get(name, default)
                    return value[0] if isinstance(value, list) else value

                memory = parameter("memory", 7168)
                parallelism = parameter("parallelism", 1)
                phc = (
                    f"$argon2id$v=19$m={memory},t={iterations},p={parallelism}"
                    f"${b64(salt)}${b64(digest)}"
                )
            else:
                phc = f"${spec['algorithm']}$i={iterations}${b64(salt)}${b64(digest)}"
            self.add_secret(phc, f"NORMALIZED_HASH_{username.upper()}")
            expected[username] = phc
        return expected

    def verify_hash_persistence(self, after_password_change=False):
        expected = self.normalized_expected_credentials()
        evidence_key = "hash_after_password_change" if after_password_change else "hash_unchanged"
        oracle = "Rust in-memory integration acceptance"
        if self.args.backend == "in-memory":
            self.report["target"][evidence_key] = f"PASS ({oracle})"
            return
        actual = []
        if self.args.backend == "json-file":
            snapshot = load_json(self.work / "target.json")

            def collect(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key == "secret_data":
                            if isinstance(item, list):
                                item = bytes(item)
                            if isinstance(item, bytes):
                                item = item.decode(errors="ignore")
                            if isinstance(item, str) and item.startswith("$"):
                                actual.append(item)
                        else:
                            collect(item)
                elif isinstance(value, list):
                    for item in value:
                        collect(item)

            collect(snapshot)
        elif self.args.backend == "sqlite":
            import sqlite3

            with sqlite3.connect(self.work / "target.sqlite") as connection:
                rows = connection.execute(
                    "SELECT secret_data FROM credentials WHERE credential_type = 'password'"
                ).fetchall()
            actual = [row[0].decode() for row in rows]
        else:
            output = self.run_command([
                "docker", "compose", "-p", self.compose_project,
                "-f", str(self.work / "compose.yaml"),
                "exec", "-T", "postgres", "psql", "-U", self.target_psql_user,
                "-d", "issuerd_target", "-At", "-c",
                "SELECT encode(secret_data, 'hex') FROM credentials WHERE credential_type = 'password'",
            ], secret_output=True)
            actual = [bytes.fromhex(line).decode() for line in output.decode().splitlines() if line]
        for username, phc in expected.items():
            if after_password_change and username == "bob-p256-current":
                continue
            if actual.count(phc) != 1:
                raise Failure(f"imported hash was rewritten or duplicated for {username}")
        self.report["target"][evidence_key] = "PASS (read-only backend oracle; other users unchanged)"

    def verify_password_change(self):
        users = self.admin("GET", f"/admin/realms/{REALM}/users?max=1000")[1]
        bob = next(user for user in users if user["username"] == "bob-p256-current")
        new_password = secrets.token_urlsafe(24)
        self.add_secret(new_password, "CHANGED_PASSWORD")
        self.admin(
            "PUT",
            f"/admin/realms/{REALM}/users/{bob['id']}/reset-password",
            body={"type": "password", "value": new_password, "temporary": False},
            expected=(204,),
        )
        old_status, _ = self.password_grant("bob-p256-current", self.secrets["users"]["bob-p256-current"])
        if old_status not in (400, 401):
            raise Failure("old password still works after ordinary password change")
        new_status, _ = self.password_grant(
            "bob-p256-current",
            new_password,
            second=self.args.backend == "postgres-redis",
        )
        if new_status != 200:
            raise Failure("new password does not work after ordinary password change")
        self.secrets["users"]["bob-p256-current"] = new_password
        _, credentials, _ = self.admin("GET", f"/admin/realms/{REALM}/users/{bob['id']}/credentials")
        for credential in credentials:
            metadata = credential.get("credential_data") or credential.get("credentialData") or "{}"
            if credential.get("type") == "password" and "argon2id" not in metadata:
                raise Failure("ordinary password change did not write Argon2id metadata")
            serialized = json.dumps(credential)
            if credential.get("secretData") or credential.get("secret_data") or credential.get("value"):
                raise Failure("admin credential response exposed secret material")
            if any(salt in serialized for salt in re.findall(r"a2V5[A-Za-z0-9_-]+", serialized)):
                raise Failure("credential metadata appears to contain a salt")
        self.report["target"]["ordinary_password_change"] = "argon2id_only_for_changed_user"

    def scan_logs(self):
        if not self.target_log.exists():
            return
        raw = self.target_log.read_text(encoding="utf-8", errors="replace")
        for secret in self.redactions:
            if secret and secret in raw:
                raise Failure("secret canary found in Issuerd logs")
        sanitized = self.sanitize(raw)
        (self.evidence / "issuerd-redacted.log").write_text(sanitized, encoding="utf-8")
        second_log = getattr(self, "second_log", None)
        if second_log and second_log.exists():
            second_raw = second_log.read_text(encoding="utf-8", errors="replace")
            for secret in self.redactions:
                if secret and secret in second_raw:
                    raise Failure("secret canary found in second-node Issuerd logs")
            (self.evidence / "issuerd-node2-redacted.log").write_text(
                self.sanitize(second_raw),
                encoding="utf-8",
            )

    def cleanup_compose(self):
        if not self.compose_project:
            return
        base = [
            "docker", "compose", "-p", self.compose_project,
            "-f", str(self.work / "compose.yaml"),
        ]
        logs = subprocess.run(
            base + ["logs", "--no-color"],
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        (self.evidence / "keycloak-redacted.log").write_text(
            self.sanitize(logs.stdout.decode(errors="replace")),
            encoding="utf-8",
        )
        down = subprocess.run(
            base + ["down", "-v", "--remove-orphans"],
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        if down.returncode != 0 and self.report["status"] == "PASS":
            self.report["status"] = "FAIL"
            self.report["error"] = "failed to remove the disposable Keycloak stack"

    def write_evidence(self):
        self.report["target"]["commit"] = self.run_command(["git", "rev-parse", "HEAD"]).decode().strip()
        self.report["target"]["version"] = self.build_target().name
        result_path = self.evidence / "keycloak-migration-result.json"
        result_path.write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        suite = ET.Element("testsuite", {
            "name": "keycloak-migration",
            "tests": str(max(1, len(self.report["users"]) + len(self.report["negative_cases"]))),
            "failures": "0" if self.report["status"] == "PASS" else "1",
        })
        if self.report["status"] == "PASS":
            for user in self.report["users"]:
                ET.SubElement(suite, "testcase", {"name": f"login:{user['username']}"})
            for case in self.report["negative_cases"]:
                ET.SubElement(suite, "testcase", {"name": f"negative:{case['case']}"})
        else:
            case = ET.SubElement(suite, "testcase", {"name": "migration"})
            ET.SubElement(case, "failure", {"message": self.sanitize(self.report.get("error", "unknown failure"))})
        ET.ElementTree(suite).write(self.evidence / "keycloak-migration-junit.xml", encoding="utf-8", xml_declaration=True)

    def verify_evidence_sanitized(self):
        for path in self.evidence.iterdir():
            if not path.is_file():
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            for secret in self.redactions:
                if secret and secret in content:
                    raise Failure(f"secret canary found in evidence file {path.name}")

    def run(self):
        try:
            self.target_port = self.target_port or free_port()
            self.prepare_fixture()
            prepare_target_infrastructure(self)
            self.acquire_target_lock()
            self.start_target()
            self.create_target_realm()
            self.verify_inventory()
            self.verify_logins_and_claims()
            self.verify_hash_persistence()
            if self.args.backend == "postgres-redis":
                start_second_target(self)
                verify_second_node_logins(self)
            self.verify_password_change()
            if self.args.backend == "postgres-redis":
                verify_second_node_logins(self)
            if self.args.backend in ("json-file", "sqlite", "postgres", "postgres-redis"):
                self.stop_target()
                self.start_target()
                if self.args.backend == "postgres-redis":
                    start_second_target(self)
                self.verify_logins_and_claims(restart=True)
                self.verify_hash_persistence(after_password_change=True)
                if self.args.backend == "postgres-redis":
                    verify_second_node_logins(self, restart=True)
            self.scan_logs()
            self.report["status"] = "PASS"
        except Exception as error:
            self.report["status"] = "FAIL"
            self.report["error"] = self.sanitize(str(error))
        finally:
            self.stop_target()
            self.release_target_lock()
            self.cleanup_compose()
            try:
                self.scan_logs()
            except Exception as error:
                self.report["status"] = "FAIL"
                self.report["error"] = self.sanitize(str(error))
            self.write_evidence()
            try:
                self.verify_evidence_sanitized()
            except Exception as error:
                self.report["status"] = "FAIL"
                self.report["error"] = self.sanitize(str(error))
                self.write_evidence()
            self.temp.cleanup()
        return self.report["status"] == "PASS"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", help="sanitized full Keycloak realm export")
    parser.add_argument("--synthetic", action="store_true", help="generate a local compatible fixture instead of running source Keycloak")
    parser.add_argument("--manifest", help="fixture manifest (default: fixture-manifest.json beside fixture)")
    parser.add_argument("--secrets", help="local-only secret input (default: fixture-secrets.json beside fixture)")
    parser.add_argument("--backend", choices=["in-memory", "json-file", "sqlite", "postgres", "postgres-redis"], default="in-memory")
    parser.add_argument("--issuerd-bin", help="Issuerd binary to test (default: target/debug/issuerd, built when missing)")
    parser.add_argument("--evidence-dir", type=pathlib.Path, help="sanitized evidence output directory")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.synthetic and args.fixture:
        raise SystemExit("--synthetic and --fixture are mutually exclusive")
    if args.manifest and not args.fixture:
        raise SystemExit("--manifest requires --fixture")
    if args.secrets and not args.fixture:
        raise SystemExit("--secrets requires --fixture")
    harness = Harness(args)
    try:
        passed = harness.run()
    except Exception as error:
        print(harness.sanitize(str(error)), file=sys.stderr)
        return 2
    if not passed:
        print(harness.sanitize(harness.report.get("error", "migration failed")), file=sys.stderr)
        print(f"evidence={harness.evidence}", file=sys.stderr)
        return 1
    print("KEYCLOAK_MIGRATION_OK")
    print(f"source={harness.report['source'].get('provenance', 'keycloak')} keycloak {KEYCLOAK_VERSION}")
    print("credential_families=argon2id,pbkdf2-sha256,pbkdf2-sha512")
    print("password_reset_required=false")
    print("post_import_login=PASS for every enabled fixture user")
    print("client_scopes=PASS")
    print("protocol_mappers=PASS")
    print("role_and_group_assignments=PASS")
    print("negative_cases=PASS")
    print(f"evidence={harness.evidence}")


def source_admin(harness, method, path, body=None, expected=(200, 204)):
    return harness.http(
        method,
        f"{harness.source_base}admin{path}",
        body=body,
        token=harness.source_admin_token,
        expected=expected,
    )


def source_list(harness, path):
    return source_admin(harness, "GET", path)[1]


def source_create_realm(harness):
    source_admin(harness, "POST", "/realms", body={
        "realm": REALM,
        "enabled": True,
        "sslRequired": "none",
    }, expected=(201,))
    profile = source_list(harness, f"/realms/{REALM}/users/profile")
    source_admin(
        harness,
        "PUT",
        f"/realms/{REALM}/users/profile",
        body={**profile, "unmanagedAttributePolicy": "ADMIN_EDIT"},
        expected=(200, 204),
    )
    profile = source_list(harness, f"/realms/{REALM}/users/profile")
    if profile.get("unmanagedAttributePolicy") != "ADMIN_EDIT":
        raise Failure(f"source User Profile rejected ADMIN_EDIT: {profile.get('unmanagedAttributePolicy')!r}")
    harness.report["source"]["unmanaged_attribute_policy"] = "ADMIN_EDIT"
    composites_path = f"/realms/{REALM}/roles/default-roles-{REALM}/composites"
    composites = source_list(harness, composites_path)
    if composites:
        source_admin(harness, "DELETE", composites_path, body=composites, expected=(204,))
    for scope in source_list(harness, f"/realms/{REALM}/client-scopes"):
        if scope.get("name") == "roles":
            continue
        try:
            source_admin(harness, "DELETE", f"/realms/{REALM}/client-scopes/{scope['id']}", expected=(204,))
        except Failure as error:
            raise Failure(f"could not delete built-in client scope {scope.get('name')}: {error}")
    source_prune_unsupported_mappers(harness)


def source_prune_unsupported_mappers(harness):
    supported = {mapper["protocolMapper"] for mapper in default_mappers()}
    removed = []
    for client in source_list(harness, f"/realms/{REALM}/clients"):
        detail = source_list(harness, f"/realms/{REALM}/clients/{client['id']}")
        for protocol_mapper in detail.get("protocolMappers", []):
            if protocol_mapper["protocolMapper"] not in supported:
                source_admin(
                    harness,
                    "DELETE",
                    f"/realms/{REALM}/clients/{client['id']}/protocol-mappers/models/{protocol_mapper['id']}",
                    expected=(204,),
                )
                removed.append(f"{detail['clientId']}:{protocol_mapper['name']}")
    for scope in source_list(harness, f"/realms/{REALM}/client-scopes"):
        detail = source_list(harness, f"/realms/{REALM}/client-scopes/{scope['id']}")
        for protocol_mapper in detail.get("protocolMappers", []):
            if protocol_mapper["protocolMapper"] not in supported:
                source_admin(
                    harness,
                    "DELETE",
                    f"/realms/{REALM}/client-scopes/{scope['id']}/protocol-mappers/models/{protocol_mapper['id']}",
                    expected=(204,),
                )
                removed.append(f"{scope['name']}:{protocol_mapper['name']}")
    harness.report["source"]["unsupported_builtin_mappers_removed_via_admin_api"] = removed


def source_client_and_scopes(harness):
    secret = harness.secrets["client_secret"]
    source_admin(harness, "POST", f"/realms/{REALM}/clients", body={
        "clientId": CLIENT_ID,
        "secret": secret,
        "publicClient": False,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": True,
        "fullScopeAllowed": False,
        "redirectUris": ["http://localhost:8080/cb"],
        "webOrigins": ["http://localhost:8080"],
    }, expected=(201,))
    source_admin(harness, "POST", f"/realms/{REALM}/clients", body={
        "clientId": PUBLIC_CLIENT_ID,
        "publicClient": True,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": True,
        "fullScopeAllowed": False,
        "redirectUris": ["http://localhost:8080/public-cb"],
        "webOrigins": ["http://localhost:8080"],
    }, expected=(201,))
    public_client = source_list(harness, f"/realms/{REALM}/clients?clientId={PUBLIC_CLIENT_ID}")[0]
    client = source_list(harness, f"/realms/{REALM}/clients?clientId={CLIENT_ID}")[0]
    scope_ids = {}
    for scope in role_resources()["clientScopes"]:
        source_admin(harness, "POST", f"/realms/{REALM}/client-scopes", body={
            "name": scope["name"],
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false",
            },
        }, expected=(201,))
        created = next(
            candidate
            for candidate in source_list(harness, f"/realms/{REALM}/client-scopes")
            if candidate["name"] == scope["name"]
        )
        scope_ids[scope["name"]] = created["id"]
        for protocol_mapper in scope["protocolMappers"]:
            try:
                source_admin(
                    harness,
                    "POST",
                    f"/realms/{REALM}/client-scopes/{created['id']}/protocol-mappers/models",
                    body=protocol_mapper,
                    expected=(201,),
                )
            except Failure as error:
                raise Failure(
                    f"could not create mapper {protocol_mapper['name']} on {scope['name']}: {error}"
                )
    for target_client in (client, public_client):
        source_admin(
            harness,
            "PUT",
            f"/realms/{REALM}/clients/{target_client['id']}/default-client-scopes/{scope_ids['migration-default']}",
            expected=(204,),
        )
        source_admin(
            harness,
            "PUT",
            f"/realms/{REALM}/clients/{target_client['id']}/optional-client-scopes/{scope_ids['migration-optional']}",
            expected=(204,),
        )
    source_admin(harness, "PUT", f"/realms/{REALM}/default-default-client-scopes/{scope_ids['migration-default']}", expected=(204,))
    source_admin(harness, "PUT", f"/realms/{REALM}/default-optional-client-scopes/{scope_ids['migration-optional']}", expected=(204,))
    return client, scope_ids


def source_roles_and_group(harness, client, scope_ids):
    definitions = role_resources()["roles"]
    realm_roles = {}
    for role in definitions["realm"]:
        source_admin(harness, "POST", f"/realms/{REALM}/roles", body={"name": role["name"]}, expected=(201,))
        realm_roles[role["name"]] = source_list(harness, f"/realms/{REALM}/roles/{role['name']}")
    client_roles = {}
    for role in definitions["client"][CLIENT_ID]:
        source_admin(
            harness,
            "POST",
            f"/realms/{REALM}/clients/{client['id']}/roles",
            body={"name": role["name"]},
            expected=(201,),
        )
        client_roles[role["name"]] = source_list(
            harness,
            f"/realms/{REALM}/clients/{client['id']}/roles/{role['name']}",
        )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/roles/migration-realm-composite/composites",
        body=[realm_roles["migration-realm-role"]],
    )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/clients/{client['id']}/roles/migration-client-composite/composites",
        body=[client_roles["migration-client-role"]],
    )
    source_admin(harness, "POST", f"/realms/{REALM}/groups", body={"name": "developers"}, expected=(201,))
    group = source_list(harness, f"/realms/{REALM}/groups?search=developers")[0]
    realm_mapping = [realm_roles["migration-realm-role"], realm_roles["group-realm-role"]]
    client_mapping = [client_roles["migration-client-role"], client_roles["group-client-role"]]
    for role in realm_mapping:
        source_admin(harness, "POST", f"/realms/{REALM}/groups/{group['id']}/role-mappings/realm", body=[role])
    for role in client_mapping:
        source_admin(
            harness,
            "POST",
            f"/realms/{REALM}/groups/{group['id']}/role-mappings/clients/{client['id']}",
            body=[role],
        )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/clients/{client['id']}/scope-mappings/realm",
        body=realm_mapping,
    )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/clients/{client['id']}/scope-mappings/clients/{client['id']}",
        body=client_mapping,
    )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/client-scopes/{scope_ids['migration-default']}/scope-mappings/realm",
        body=realm_mapping,
    )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/client-scopes/{scope_ids['migration-default']}/scope-mappings/clients/{client['id']}",
        body=client_mapping,
    )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/client-scopes/{scope_ids['migration-optional']}/scope-mappings/realm",
        body=realm_mapping,
    )
    source_admin(
        harness,
        "POST",
        f"/realms/{REALM}/client-scopes/{scope_ids['migration-optional']}/scope-mappings/clients/{client['id']}",
        body=client_mapping,
    )
    return realm_roles, client_roles, group


def source_users(harness, realm_roles, client_roles, group):
    specifications = [
        ("alice-argon2id", "argon2id", 5, "argon2"),
        ("bob-p256-current", "pbkdf2-sha256", 600_000, "pbkdf2-sha256"),
        ("carol-p512-current", "pbkdf2-sha512", 210_000, "pbkdf2-sha512"),
        ("dave-p256-legacy", "pbkdf2-sha256", 27_500, "pbkdf2-sha256"),
        ("erin-p512-legacy", "pbkdf2-sha512", 27_500, "pbkdf2-sha512"),
    ]
    server_info = source_list(harness, "/serverinfo")
    harness.report["source"]["password_hash_providers"] = (
        server_info.get("providers", {}).get("passwordHashing", {})
    )
    user_specs = []
    for username, algorithm, iterations, keycloak_algorithm in specifications:
        password = secrets.token_urlsafe(24)
        harness.secrets["users"][username] = password
        harness.add_secret(password, f"PASSWORD_{username.upper()}")
        policy = f"hashAlgorithm({keycloak_algorithm}) and hashIterations({iterations})"
        source_admin(harness, "PUT", f"/realms/{REALM}", body={"passwordPolicy": policy}, expected=(204,))
        current_policy = source_list(harness, f"/realms/{REALM}").get("passwordPolicy")
        if current_policy != policy:
            raise Failure(
                f"password policy was not applied for {username}: {current_policy!r} != {policy!r}"
            )
        representation = user_representation(username, password, {
            "type": "password",
            "value": password,
            "temporary": False,
        })
        source_admin(harness, "POST", f"/realms/{REALM}/users", body=representation, expected=(201,))
        user = source_list(harness, f"/realms/{REALM}/users?username={username}&exact=true")[0]
        source_admin(
            harness,
            "PUT",
            f"/realms/{REALM}/users/{user['id']}",
            body={**user, "attributes": representation["attributes"]},
            expected=(204,),
        )
        if username == "alice-argon2id":
            attribute_rows = harness.run_command([
                "docker", "compose", "-p", harness.compose_project,
                "-f", str(harness.work / "compose.yaml"),
                "exec", "-T", "postgres", "psql", "-U", "keycloak", "-d", "keycloak",
                "-At", "-F", "\t", "-c",
                "SELECT ua.name,ua.value FROM user_attribute ua "
                "JOIN user_entity u ON ua.user_id=u.id "
                f"WHERE u.username='{username}' ORDER BY ua.name,ua.value",
            ], secret_output=True).decode().splitlines()
            attributes = [tuple(line.split("\t", 1)) for line in attribute_rows]
            harness.report["source"]["user_attribute_oracle"] = {
                username: sorted(name for name, _ in attributes),
            }
            if ("optionalnote", "optional-value") not in attributes:
                values = [value for name, value in attributes if name == "optionalnote"]
                raise Failure(
                    "Keycloak did not persist the expected optionalnote through the Admin API; "
                    f"database values={values!r}"
                )
        source_admin(
            harness,
            "PUT",
            f"/realms/{REALM}/users/{user['id']}/reset-password",
            body={"type": "password", "value": password, "temporary": False},
            expected=(204,),
        )
        if username == "alice-argon2id":
            source_admin(
                harness,
                "POST",
                f"/realms/{REALM}/users/{user['id']}/role-mappings/realm",
                body=[realm_roles["migration-realm-composite"]],
            )
            source_admin(
                harness,
                "POST",
                f"/realms/{REALM}/users/{user['id']}/role-mappings/clients/{harness.source_client['id']}",
                body=[client_roles["migration-client-composite"]],
            )
            source_admin(
                harness,
                "PUT",
                f"/realms/{REALM}/users/{user['id']}/groups/{group['id']}",
                expected=(204,),
            )
        parameters = {"t": 5, "m": 7168, "p": 1, "hash_length": 32} if algorithm == "argon2id" else {"iterations": iterations}
        user_specs.append({
            "username": username,
            "algorithm": algorithm,
            "enabled": True,
            "parameters": parameters,
        })
    source_admin(harness, "PUT", f"/realms/{REALM}", body={
        "passwordPolicy": "hashAlgorithm(pbkdf2-sha256) and hashIterations(27500)",
    }, expected=(204,))
    disabled_password = secrets.token_urlsafe(24)
    harness.secrets["users"]["disabled-user"] = disabled_password
    harness.add_secret(disabled_password, "PASSWORD_DISABLED_USER")
    source_admin(harness, "POST", f"/realms/{REALM}/users", body=user_representation(
        "disabled-user",
        disabled_password,
        {"type": "password", "value": disabled_password, "temporary": False},
        enabled=False,
    ), expected=(201,))
    source_admin(harness, "POST", f"/realms/{REALM}/users", body=user_representation("no-password", None), expected=(201,))
    history_password = secrets.token_urlsafe(24)
    harness.secrets["users"]["history-only"] = history_password
    harness.add_secret(history_password, "PASSWORD_HISTORY_ONLY")
    source_admin(harness, "POST", f"/realms/{REALM}/users", body=user_representation(
        "history-only",
        history_password,
        {"type": "password", "value": history_password, "temporary": False},
    ), expected=(201,))
    return user_specs


def source_policy_for_spec(harness, spec):
    algorithm = "argon2" if spec["algorithm"] == "argon2id" else spec["algorithm"]
    iterations = spec["parameters"].get("t", spec["parameters"].get("iterations"))
    source_admin(harness, "PUT", f"/realms/{REALM}", body={
        "passwordPolicy": f"hashAlgorithm({algorithm}) and hashIterations({iterations})",
    }, expected=(204,))


def source_login_checks(harness):
    for spec in harness.manifest["users"]:
        username = spec["username"]
        source_policy_for_spec(harness, spec)
        status, token = harness.password_grant(
            username,
            harness.secrets["users"][username],
            source=True,
        )
        if status != 200:
            user = source_list(harness, f"/realms/{REALM}/users?username={username}&exact=true")[0]
            raise Failure(
                f"source Keycloak login failed for {username}: {token}; "
                f"requiredActions={user.get('requiredActions')}"
            )
        spec["source_login"] = "PASS"
        wrong_status, _ = harness.password_grant(username, secrets.token_urlsafe(24), source=True)
        if wrong_status not in (400, 401):
            raise Failure(f"source Keycloak accepted a wrong password for {username}")
    for username in ["disabled-user", "no-password"]:
        status, _ = harness.password_grant(
            username,
            harness.secrets["users"].get(username) or secrets.token_urlsafe(24),
            source=True,
        )
        if status not in (400, 401):
            raise Failure(f"source Keycloak accepted negative user {username}")
    source_policy_for_spec(harness, harness.manifest["users"][0])
    status, token = harness.password_grant(
        "alice-argon2id",
        harness.secrets["users"]["alice-argon2id"],
        "openid migration-default",
        source=True,
    )
    if status != 200:
        raise Failure("source claim-check login failed")
    claims = harness.userinfo(token["access_token"], source=True)
    expected = {key: claims[key] for key in [
        "dept",
        "given_name_custom",
        "name",
        "address",
        "groups",
        "realm_access",
        "resource_access",
        "aud",
        "allowed_origins",
    ] if key in claims}
    client_detail = source_list(harness, f"/realms/{REALM}/clients/{harness.source_client['id']}")
    if "migration-optional" not in client_detail.get("optionalClientScopes", []):
        raise Failure(f"source optional client scope is not assigned: {client_detail.get('optionalClientScopes')}")
    harness.report["source"]["migration_check_scope_assignments"] = {
        "default": client_detail.get("defaultClientScopes"),
        "optional": client_detail.get("optionalClientScopes"),
    }
    optional_scope = next(
        scope for scope in source_list(harness, f"/realms/{REALM}/client-scopes")
        if scope["name"] == "migration-optional"
    )
    optional_mapper = optional_scope.get("protocolMappers", [{}])[0]
    if optional_mapper.get("config", {}).get("user.attribute") != "optionalnote":
        raise Failure(f"source optional mapper has the wrong input attribute: {optional_mapper}")
    if optional_mapper.get("config", {}).get("userinfo.token.claim") != "true":
        raise Failure(f"source optional mapper is not enabled for UserInfo: {optional_mapper}")
    alice = source_list(harness, f"/realms/{REALM}/users?username=alice-argon2id&exact=true")[0]
    if "optionalnote" not in alice.get("attributes", {}):
        raise Failure(f"source user has no optionalnote attribute: {alice.get('attributes')}")
    optional_status, optional_token = harness.password_grant(
        "alice-argon2id",
        harness.secrets["users"]["alice-argon2id"],
        "openid migration-default migration-optional",
        source=True,
    )
    if optional_status != 200:
        raise Failure("source optional-scope login failed")
    optional_claims = harness.userinfo(optional_token["access_token"], source=True)
    if optional_claims.get("optional_claim") != "optional-value":
        raise Failure(
            f"source optional scope claim is missing: {optional_claims.get('optional_claim')!r}; "
            f"token_scope={optional_token.get('scope')!r}"
        )
    harness.manifest["claim_checks"] = [{
        "username": "alice-argon2id",
        "scope": "openid migration-default",
        "expect": expected,
        "forbid": ["optional_claim"],
    }, {
        "username": "alice-argon2id",
        "scope": "openid migration-default migration-optional",
        "expect": {"optional_claim": "optional-value"},
        "forbid": [],
    }]
    harness.verify_non_member(source=True)


def source_export_and_oracle(harness):
    harness.run_command([
        "docker", "compose", "-p", harness.compose_project,
        "-f", str(harness.work / "compose.yaml"), "stop", "keycloak",
    ], secret_output=True)
    export_dir = harness.work / "export"
    export_dir.mkdir(mode=0o700)
    harness.run_command([
        "docker", "compose", "-p", harness.compose_project,
        "-f", str(harness.work / "compose.yaml"),
        "run", "--rm", "--no-deps",
        "-v", f"{export_dir}:/export",
        "keycloak", "export", "--dir", "/export", "--realm", REALM, "--users", "realm_file",
    ], secret_output=True, timeout=600)
    export_path = export_dir / f"{REALM}-realm.json"
    raw = export_path.read_bytes()
    document = json.loads(raw)
    if not document.get("users") or not document.get("clientScopes"):
        raise Failure("Keycloak export is missing users or client scopes")
    source_client = next(
        client for client in document.get("clients", []) if client.get("clientId") == CLIENT_ID
    )
    harness.report["source"]["migration_check_scope_assignments"] = {
        "default": source_client.get("defaultClientScopes"),
        "optional": source_client.get("optionalClientScopes"),
    }
    users = {user["username"]: user for user in document["users"]}
    harness.report["source"]["exported_argon2_credential_data"] = (
        users["alice-argon2id"]["credentials"][0].get("credentialData")
    )
    for spec in harness.manifest["users"]:
        user = users.get(spec["username"])
        if not user or not user.get("credentials"):
            raise Failure(f"Keycloak export has no credentials for {spec['username']}")
    default_scope = next((scope for scope in document["clientScopes"] if scope["name"] == "migration-default"), None)
    if not default_scope or len(default_scope.get("protocolMappers", [])) != 9:
        raise Failure("Keycloak export does not contain all nine protocol mappers")
    oracle_sql = (
        "SELECT u.username,c.type,c.credential_data,c.secret_data "
        "FROM credential c JOIN user_entity u ON c.user_id=u.id "
        "JOIN realm r ON u.realm_id=r.id "
        f"WHERE r.name='{REALM}' AND c.type IN ('password','password-history') "
        "ORDER BY u.username,c.priority"
    )
    output = harness.run_command([
        "docker", "compose", "-p", harness.compose_project,
        "-f", str(harness.work / "compose.yaml"),
        "exec", "-T", "postgres", "psql", "-U", "keycloak", "-d", "keycloak",
        "-At", "-F", "\t", "-c", oracle_sql,
    ], secret_output=True)
    rows = {}
    for line in output.decode().splitlines():
        username, credential_type, credential_data, secret_data = line.split("\t", 3)
        harness.add_secret(credential_data, "ORACLE_CREDENTIAL_DATA")
        harness.add_secret(secret_data, "ORACLE_SECRET_DATA")
        rows.setdefault(username, []).append((credential_type, json.loads(credential_data), json.loads(secret_data)))
    for spec in harness.manifest["users"]:
        credentials = rows.get(spec["username"], [])
        password_rows = [row for row in credentials if row[0] == "password"]
        if len(password_rows) != 1:
            raise Failure(f"credential oracle expected one password row for {spec['username']}")
        _, credential_data, secret_data = password_rows[0]
        algorithm = credential_data.get("algorithm")
        expected_algorithm = "argon2" if spec["algorithm"] == "argon2id" else spec["algorithm"]
        if algorithm != expected_algorithm:
            raise Failure(
                f"credential oracle algorithm mismatch for {spec['username']}: "
                f"{algorithm!r} != {expected_algorithm!r}; metadata_keys={sorted(credential_data)}"
            )
        expected_iterations = spec["parameters"].get("t", spec["parameters"].get("iterations"))
        if credential_data.get("hashIterations") != expected_iterations:
            raise Failure(f"credential oracle iteration mismatch for {spec['username']}")
        if not secret_data.get("value") or not secret_data.get("salt"):
            raise Failure(f"credential oracle has an empty hash or salt for {spec['username']}")
        if spec["algorithm"] == "argon2id":
            data = credential_data.get(
                "algorithmData",
                credential_data.get("additionalParameters", {}),
            )
            expected = {"version": "1.3", "type": "id", "hashLength": "32", "memory": "7168", "parallelism": "1"}
            for key, value in expected.items():
                if data.get(key) not in ([value], value):
                    raise Failure(
                        f"credential oracle Argon2 parameter mismatch for {spec['username']}: "
                        f"{key}={data.get(key)!r}"
                    )
        spec["oracle"] = "PASS"
    history_user = users.get("history-only")
    if history_user and history_user.get("credentials"):
        history_user["credentials"][0]["type"] = "password-history"
    harness.report["source"]["credential_oracle"] = "PASS"
    harness.report["source"]["source_logins"] = "PASS"
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode(), document


def generate_keycloak_fixture(harness):
    harness.compose_project = f"issuerd-kc-migration-{os.getpid()}-{secrets.token_hex(4)}"
    postgres_password = secrets.token_urlsafe(32)
    keycloak_admin = secrets.token_urlsafe(32)
    harness.add_secret(postgres_password, "SOURCE_POSTGRES_PASSWORD")
    harness.add_secret(keycloak_admin, "SOURCE_ADMIN_PASSWORD")
    harness.secrets = {"users": {}, "client_secret": secrets.token_urlsafe(32)}
    harness.add_secret(harness.secrets["client_secret"], "SOURCE_CLIENT_SECRET")
    kc_port = free_port()
    management_port = free_port()
    harness.source_postgres_password = postgres_password
    harness.source_postgres_port = free_port()
    harness.source_redis_port = free_port()
    harness.source_base = f"http://127.0.0.1:{kc_port}/"
    compose = f"""services:
  postgres:
    image: {POSTGRES_IMAGE}
    environment:
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: {postgres_password}
      POSTGRES_DB: keycloak
    ports:
      - "127.0.0.1:{harness.source_postgres_port}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 3s
      timeout: 3s
      retries: 30
  redis:
    image: redis:7.2-alpine
    command: ["redis-server", "--maxmemory", "256mb", "--maxmemory-policy", "noeviction"]
    ports:
      - "127.0.0.1:{harness.source_redis_port}:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 3s
      retries: 30
  keycloak:
    image: {KEYCLOAK_IMAGE}
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: {postgres_password}
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: {keycloak_admin}
      KC_HEALTH_ENABLED: "true"
      KC_HTTP_ENABLED: "true"
      KC_HOSTNAME_STRICT: "false"
      KC_SPI_PASSWORD_HASHING_ARGON2_VERSION: "1.3"
      KC_SPI_PASSWORD_HASHING_ARGON2_TYPE: id
      KC_SPI_PASSWORD_HASHING_ARGON2_HASH_LENGTH: "32"
      KC_SPI_PASSWORD_HASHING_ARGON2_MEMORY: "7168"
      KC_SPI_PASSWORD_HASHING_ARGON2_ITERATIONS: "5"
      KC_SPI_PASSWORD_HASHING_ARGON2_PARALLELISM: "1"
    ports:
      - "127.0.0.1:{kc_port}:8080"
      - "127.0.0.1:{management_port}:9000"
    command: ["start-dev", "--hostname=localhost", "--hostname-strict=false", "--http-enabled=true"]
"""
    (harness.work / "compose.yaml").write_text(compose, encoding="utf-8")
    os.chmod(harness.work / "compose.yaml", 0o600)
    harness.run_command([
        "docker", "compose", "-p", harness.compose_project,
        "-f", str(harness.work / "compose.yaml"),
        "up", "-d", "--wait", "--wait-timeout", "300", "postgres", "redis", "keycloak",
    ], secret_output=True, timeout=360)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            _, admin_token, _ = harness.http(
                "POST",
                f"{harness.source_base}realms/master/protocol/openid-connect/token",
                form={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "admin",
                    "password": keycloak_admin,
                },
            )
            break
        except Failure:
            time.sleep(1)
    else:
        raise Failure("Keycloak master Admin API did not become ready in 180 seconds")
    harness.source_admin_token = admin_token["access_token"]
    harness.source_token = harness.secrets["client_secret"]
    harness.add_secret(harness.source_admin_token, "SOURCE_ADMIN_TOKEN")
    source_create_realm(harness)
    harness.source_client, scope_ids = source_client_and_scopes(harness)
    realm_roles, client_roles, group = source_roles_and_group(harness, harness.source_client, scope_ids)
    user_specs = source_users(harness, realm_roles, client_roles, group)
    harness.manifest = make_manifest(user_specs, f"Keycloak {KEYCLOAK_VERSION} full realm export", [])
    source_login_checks(harness)
    raw, harness.fixture = source_export_and_oracle(harness)
    digests = json.loads(harness.run_command([
        "docker", "image", "inspect", KEYCLOAK_IMAGE, "--format", "{{json .RepoDigests}}",
    ]).decode())
    harness.report["source"].update({
        "image": KEYCLOAK_IMAGE,
        "image_digest": digests[0] if digests else "unknown",
        "export_command": "kc.sh export --dir /export --realm migration-lab --users realm_file",
    })
    return raw


def start_second_target(harness):
    if harness.args.backend != "postgres-redis":
        return
    if getattr(harness, "second_process", None) is not None:
        return
    harness.second_port = getattr(harness, "second_port", None) or free_port()
    harness.run_command(
        ["docker", "build", "-t", "issuerd:keycloak-migration", "."],
        timeout=1200,
    )
    harness.second_container_name = f"issuerd-migration-node2-{os.getpid()}-{secrets.token_hex(4)}"
    harness.second_log = harness.work / "issuerd-node2.log"
    config_path = harness.work / "issuerd-node2.toml"
    config_text = harness.target_config_text(second=True).replace(
        str(harness.work / "provision.yaml"),
        "/etc/issuerd/provision.yaml",
    )
    config_text = config_text.replace("@127.0.0.1:", "@postgres:")
    config_text = config_text.replace("redis://127.0.0.1", "redis://redis")
    config_text = re.sub(r"@postgres:\d+", "@postgres:5432", config_text)
    config_text = re.sub(r"redis://redis:\d+", "redis://redis:6379", config_text)
    config_path.write_text(config_text, encoding="utf-8")
    os.chmod(config_path, 0o600)
    log = open(harness.second_log, "ab")
    harness.second_process = subprocess.Popen(
        [
            "docker", "run", "--name", harness.second_container_name,
            "--network", harness.compose_project + "_default",
            "-p", f"127.0.0.1:{harness.second_port}:{harness.second_port}",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-e", "ISSUERD_BOOTSTRAP_ADMIN_PASSWORD=" + harness.target_admin,
            "-e", "ISSUERD_CLUSTER__NODE_ID=migration-node-2",
            "-v", f"{config_path}:/etc/issuerd/issuerd.toml:ro",
            "-v", f"{harness.work / 'provision.yaml'}:/etc/issuerd/provision.yaml:ro",
            "issuerd:keycloak-migration",
            "daemon", "-c", "/etc/issuerd/issuerd.toml",
        ],
        cwd=harness.root,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    log.close()
    harness.second_base_url = f"http://127.0.0.1:{harness.second_port}/"
    deadline = time.monotonic() + 90
    last_error = None
    while time.monotonic() < deadline:
        if harness.second_process.poll() is not None:
            raise Failure("second Issuerd node exited before becoming ready")
        try:
            harness.http("GET", harness.second_base_url + "ready", expected=(200,))
            break
        except Failure as error:
            last_error = error
            time.sleep(0.25)
    else:
        raise Failure(f"second Issuerd node did not become ready in 90 seconds: {last_error}")


def stop_second_target(harness):
    process = getattr(harness, "second_process", None)
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    container_name = getattr(harness, "second_container_name", None)
    if container_name is not None:
        result = subprocess.run(
            ["docker", "rm", "-f", container_name],
            cwd=harness.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if result.returncode != 0 and b"No such container" not in result.stderr:
            raise Failure("could not remove the second Issuerd node container")
        harness.second_container_name = None
    harness.second_process = None


def verify_second_node_logins(harness, restart=False):
    for spec in harness.manifest["users"]:
        if not spec.get("enabled", True):
            continue
        username = spec["username"]
        status, _ = harness.password_grant(username, harness.secrets["users"][username], second=True)
        if status != 200:
            raise Failure(f"second-node login failed for {username}")
    harness.report["target"]["second_node_login"] = "PASS" if not restart else "PASS_AFTER_RESTART"


def prepare_target_infrastructure(harness):
    if harness.args.backend not in ("postgres", "postgres-redis"):
        return
    if harness.compose_project is None:
        harness.compose_project = f"issuerd-target-migration-{os.getpid()}-{secrets.token_hex(4)}"
        postgres_password = secrets.token_urlsafe(32)
        postgres_port = free_port()
        redis_port = free_port()
        harness.add_secret(postgres_password, "TARGET_POSTGRES_PASSWORD")
        compose = f"""services:
  postgres:
    image: {POSTGRES_IMAGE}
    environment:
      POSTGRES_USER: issuerd
      POSTGRES_PASSWORD: {postgres_password}
      POSTGRES_DB: issuerd_target
    ports:
      - "127.0.0.1:{postgres_port}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U issuerd -d issuerd_target"]
      interval: 3s
      timeout: 3s
      retries: 30
  redis:
    image: redis:7.2-alpine
    command: ["redis-server", "--maxmemory", "256mb", "--maxmemory-policy", "noeviction"]
    ports:
      - "127.0.0.1:{redis_port}:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 3s
      retries: 30
"""
        (harness.work / "compose.yaml").write_text(compose, encoding="utf-8")
        os.chmod(harness.work / "compose.yaml", 0o600)
        harness.run_command([
            "docker", "compose", "-p", harness.compose_project,
            "-f", str(harness.work / "compose.yaml"),
            "up", "-d", "--wait", "--wait-timeout", "180", "postgres", "redis",
        ], secret_output=True, timeout=240)
        harness.target_database_url = (
            f"postgres://issuerd:{postgres_password}@127.0.0.1:{postgres_port}/issuerd_target"
        )
        harness.target_redis_url = f"redis://127.0.0.1:{redis_port}"
        harness.target_psql_user = "issuerd"
    else:
        harness.run_command([
            "docker", "compose", "-p", harness.compose_project,
            "-f", str(harness.work / "compose.yaml"),
            "exec", "-T", "postgres", "psql", "-U", "keycloak", "-d", "keycloak",
            "-c", "CREATE DATABASE issuerd_target",
        ], secret_output=True)
        harness.target_database_url = (
            f"postgres://keycloak:{harness.source_postgres_password}"
            f"@127.0.0.1:{harness.source_postgres_port}/issuerd_target"
        )
        harness.target_redis_url = f"redis://127.0.0.1:{harness.source_redis_port}"
        harness.target_psql_user = "keycloak"
    provision = f"""marker: keycloak-migration-target
realms:
  - name: master
    enabled: true
    ssl_required: none
roles:
  - realm: master
    name: manage-realm
  - realm: master
    name: view-realm
  - realm: master
    name: manage-users
  - realm: master
    name: view-users
  - realm: master
    name: manage-clients
  - realm: master
    name: view-clients
users:
  - realm: master
    username: admin
    enabled: true
    password: {harness.target_admin}
    realm_roles: [manage-realm, view-realm, manage-users, view-users, manage-clients, view-clients]
clients:
  - realm: master
    client_id: admin-cli
    enabled: true
    public_client: true
    redirect_uris: ["http://127.0.0.1:{harness.target_port}/"]
    web_origins: ["http://127.0.0.1:{harness.target_port}"]
    default_scopes: [openid, profile]
    optional_scopes: [email]
"""
    (harness.work / "provision.yaml").write_text(provision, encoding="utf-8")
    os.chmod(harness.work / "provision.yaml", 0o600)


if __name__ == "__main__":
    sys.exit(main())
