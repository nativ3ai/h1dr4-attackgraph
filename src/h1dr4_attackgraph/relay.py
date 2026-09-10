from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import uuid
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .service import AttackGraphService
from .workspace_sync import (
    WorkspaceEnvelope,
    WorkspaceEnvelopeCodec,
    generate_workspace_key,
)

DEFAULT_RELAY_URL = "https://h1dr4.dev/api/v1/attackgraph"
INVITE_PREFIX = "h1dr4-ag1:"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_b64(value: dict[str, Any]) -> str:
    return _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _invite_wrap_key(secret: bytes) -> bytes:
    return hashlib.sha256(b"h1dr4-attackgraph-invite-v1\0" + secret).digest()


def _redeem_proof(secret: bytes) -> str:
    return _sha256(b"h1dr4-attackgraph-redeem-v1\0" + secret)


def _relay_url(value: str) -> str:
    raw = str(value or "").strip()
    parsed = urlsplit(raw)
    hostname = (parsed.hostname or "").lower()
    try:
        loopback = hostname == "localhost" or ip_address(hostname).is_loopback
    except ValueError:
        loopback = False
    allowed = {"h1dr4.dev", "localhost", "127.0.0.1", "::1"}
    allowed.update(
        item.strip().lower()
        for item in os.getenv("ATTACKGRAPH_RELAY_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    )
    if (
        not hostname
        or hostname not in allowed
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
    ):
        raise RelayError("relay_url_not_allowed")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _private_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _public_key(key: Ed25519PrivateKey) -> str:
    return _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


class RelayError(RuntimeError):
    pass


class RelayStateStore:
    """Small mode-0600 local state file; relay access and encryption keys never leave it."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "workspaces": {}}
        payload = json.loads(self.path.read_text())
        if payload.get("version") != 1 or not isinstance(payload.get("workspaces"), dict):
            raise RelayError("relay_state_version_unsupported")
        return payload

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.{secrets.token_hex(4)}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)
        self.path.chmod(0o600)

    def identity(self, actor_name: str = "") -> tuple[str, str, Ed25519PrivateKey]:
        state = self.load()
        actor_id = str(state.get("actor_id") or f"agt_{uuid.uuid4().hex[:12]}")
        name = str(actor_name or state.get("actor_name") or actor_id)[:100]
        encoded = str(state.get("signing_private_key") or "")
        key = (
            Ed25519PrivateKey.from_private_bytes(_unb64(encoded))
            if encoded
            else WorkspaceEnvelopeCodec.generate_signing_key()
        )
        state.update(
            {
                "actor_id": actor_id,
                "actor_name": name,
                "signing_private_key": _b64(_private_key_bytes(key)),
            }
        )
        self.save(state)
        return actor_id, name, key

    def workspace(self, workspace_id: str) -> dict[str, Any] | None:
        return self.load()["workspaces"].get(workspace_id)

    def put_workspace(self, workspace_id: str, value: dict[str, Any]) -> None:
        state = self.load()
        state["workspaces"][workspace_id] = value
        self.save(state)

    def update_cursor(self, workspace_id: str, cursor: int) -> None:
        state = self.load()
        workspace = state["workspaces"].get(workspace_id)
        if workspace is None:
            raise RelayError("relay_workspace_not_joined")
        workspace["cursor"] = max(int(workspace.get("cursor") or 0), int(cursor))
        self.save(state)

    def joined_ids(self) -> list[str]:
        return list(self.load()["workspaces"])


class AttackGraphRelayClient:
    def __init__(
        self,
        state: RelayStateStore,
        *,
        client: httpx.Client | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.state = state
        self.client = client or httpx.Client(timeout=timeout)

    @staticmethod
    def _request_error(response: httpx.Response) -> RelayError:
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        message = str(payload.get("error") or f"relay_http_{response.status_code}")
        return RelayError(message)

    def _request(
        self,
        method: str,
        url: str,
        *,
        access_token: str = "",
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = self.client.request(
                method,
                url,
                headers={"authorization": f"Bearer {access_token}"} if access_token else {},
                json=json_body,
            )
        except httpx.HTTPError as exc:
            raise RelayError("relay_unavailable") from exc
        if response.status_code >= 400:
            raise self._request_error(response)
        try:
            payload = response.json()
        except ValueError as exc:
            raise RelayError("relay_response_invalid") from exc
        if not isinstance(payload, dict):
            raise RelayError("relay_response_invalid")
        return payload

    def host_workspace(
        self,
        service: AttackGraphService,
        engagement_id: str,
        *,
        relay_url: str = DEFAULT_RELAY_URL,
        actor_name: str = "",
        bootstrap_token: str = "",
    ) -> dict[str, Any]:
        if self.state.workspace(engagement_id):
            return self.status(engagement_id)
        service.memory.get_engagement(engagement_id)
        actor_id, name, signing_key = self.state.identity(actor_name)
        service.memory.actor_id = actor_id
        service.memory.actor_name = name
        base = _relay_url(relay_url)
        payload = self._request(
            "POST",
            f"{base}/workspaces",
            access_token=bootstrap_token,
            json_body={
                "workspace_id": engagement_id,
                "title": f"Private workspace {engagement_id[-8:]}",
                "actor_id": actor_id,
                "actor_name": name,
                "signing_public_key": _public_key(signing_key),
            },
        )
        workspace_key = generate_workspace_key()
        self.state.put_workspace(
            engagement_id,
            {
                "relay_url": base,
                "workspace_key": _b64(workspace_key),
                "access_token": payload["access_token"],
                "role": "owner",
                "cursor": 0,
            },
        )
        self.push_workspace(service, engagement_id)
        return self.status(engagement_id)

    def create_invite(
        self,
        workspace_id: str,
        *,
        role: str = "operator",
        hours: int = 24,
    ) -> dict[str, Any]:
        workspace = self._workspace(workspace_id)
        secret = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        key = _unb64(workspace["workspace_key"])
        wrapped = AESGCM(_invite_wrap_key(secret)).encrypt(
            nonce,
            key,
            f"h1dr4-workspace-invite-v1\n{workspace_id}".encode(),
        )
        proof = _redeem_proof(secret)
        payload = self._request(
            "POST",
            f"{workspace['relay_url']}/workspaces/{workspace_id}/invites",
            access_token=workspace["access_token"],
            json_body={
                "role": role,
                "hours": hours,
                "redeem_proof_hash": _sha256(proof.encode()),
                "wrapped_workspace_key": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "nonce": _b64(nonce),
                    "ciphertext": _b64(wrapped),
                },
            },
        )
        invite_code = INVITE_PREFIX + _json_b64(
            {
                "version": 1,
                "relay_url": workspace["relay_url"],
                "invite_id": payload["invite_id"],
                "secret": _b64(secret),
            }
        )
        return {
            "workspace_id": workspace_id,
            "role": payload["role"],
            "expires_at": payload["expires_at"],
            "invite_code": invite_code,
            "warning": "The invite code grants access once. Send it only to the intended operator.",
        }

    def join_workspace(
        self,
        service: AttackGraphService,
        invite_code: str,
        *,
        actor_name: str,
    ) -> dict[str, Any]:
        invite = self.decode_invite(invite_code)
        base = _relay_url(str(invite["relay_url"]))
        invite_id = str(invite["invite_id"])
        secret = _unb64(str(invite["secret"]))
        metadata = self._request("GET", f"{base}/invites/{invite_id}")
        workspace_id = str(metadata["workspace_id"])
        wrapped = metadata["wrapped_workspace_key"]
        if wrapped.get("version") != 1 or wrapped.get("algorithm") != "AES-256-GCM":
            raise RelayError("invite_key_envelope_unsupported")
        try:
            workspace_key = AESGCM(_invite_wrap_key(secret)).decrypt(
                _unb64(str(wrapped["nonce"])),
                _unb64(str(wrapped["ciphertext"])),
                f"h1dr4-workspace-invite-v1\n{workspace_id}".encode(),
            )
        except Exception as exc:
            raise RelayError("invite_key_decryption_failed") from exc
        actor_id, name, signing_key = self.state.identity(actor_name)
        service.memory.actor_id = actor_id
        service.memory.actor_name = name
        joined = self._request(
            "POST",
            f"{base}/invites/{invite_id}/redeem",
            json_body={
                "redeem_proof": _redeem_proof(secret),
                "actor_id": actor_id,
                "actor_name": name,
                "signing_public_key": _public_key(signing_key),
            },
        )
        self.state.put_workspace(
            workspace_id,
            {
                "relay_url": base,
                "workspace_key": _b64(workspace_key),
                "access_token": joined["access_token"],
                "role": joined["member"]["role"],
                "cursor": 0,
            },
        )
        pulled = self.pull_workspace(service, workspace_id)
        return {**self.status(workspace_id), "pulled_events": pulled}

    def members(self, workspace_id: str) -> list[dict[str, Any]]:
        workspace = self._workspace(workspace_id)
        payload = self._request(
            "GET",
            f"{workspace['relay_url']}/workspaces/{workspace_id}/members",
            access_token=workspace["access_token"],
        )
        return list(payload.get("members") or [])

    def revoke_member(self, workspace_id: str, member_id: str) -> dict[str, Any]:
        workspace = self._workspace(workspace_id)
        if workspace.get("role") != "owner":
            raise RelayError("relay_owner_required")
        payload = self._request(
            "DELETE",
            f"{workspace['relay_url']}/workspaces/{workspace_id}/members/{member_id}",
            access_token=workspace["access_token"],
        )
        return dict(payload["member"])

    @staticmethod
    def decode_invite(invite_code: str) -> dict[str, Any]:
        if not invite_code.startswith(INVITE_PREFIX):
            raise RelayError("invite_code_invalid")
        try:
            payload = json.loads(_unb64(invite_code.removeprefix(INVITE_PREFIX)))
        except (ValueError, UnicodeDecodeError) as exc:
            raise RelayError("invite_code_invalid") from exc
        if payload.get("version") != 1 or not all(
            payload.get(key) for key in ("relay_url", "invite_id", "secret")
        ):
            raise RelayError("invite_code_invalid")
        return payload

    def pull_workspace(self, service: AttackGraphService, workspace_id: str) -> int:
        workspace = self._workspace(workspace_id)
        codec = WorkspaceEnvelopeCodec(_unb64(workspace["workspace_key"]))
        cursor = int(workspace.get("cursor") or 0)
        pulled = 0
        while True:
            previous_cursor = cursor
            payload = self._request(
                "GET",
                f"{workspace['relay_url']}/workspaces/{workspace_id}/events?after={cursor}&limit=25",
                access_token=workspace["access_token"],
            )
            events = payload.get("events") or []
            if not isinstance(events, list):
                raise RelayError("relay_events_invalid")
            if not events:
                break
            for row in events:
                try:
                    envelope = WorkspaceEnvelope(
                        **{
                            key: row[key]
                            for key in (
                                "version",
                                "workspace_id",
                                "event_id",
                                "actor_id",
                                "created_at",
                                "nonce",
                                "ciphertext",
                                "ciphertext_hash",
                                "signing_public_key",
                                "signature",
                            )
                        }
                    )
                    if envelope.workspace_id != workspace_id:
                        raise ValueError("relay_event_workspace_mismatch")
                    opened = codec.open(envelope)
                    if opened.get("kind") != "workspace.snapshot":
                        raise ValueError("relay_event_kind_unsupported")
                    service.memory.import_workspace(opened["snapshot"])
                    cursor = max(cursor, int(row["cursor"]))
                    pulled += 1
                except Exception as exc:
                    raise RelayError("relay_event_invalid") from exc
            if cursor <= previous_cursor:
                raise RelayError("relay_cursor_not_advanced")
            self.state.update_cursor(workspace_id, cursor)
        return pulled

    def pull_all(self, service: AttackGraphService) -> int:
        return sum(
            self.pull_workspace(service, workspace_id) for workspace_id in self.state.joined_ids()
        )

    def push_workspace(self, service: AttackGraphService, workspace_id: str) -> dict[str, Any]:
        workspace = self._workspace(workspace_id)
        if workspace.get("role") == "observer":
            raise RelayError("relay_observer_cannot_write")
        state = self.state.load()
        signing_key = Ed25519PrivateKey.from_private_bytes(
            _unb64(str(state["signing_private_key"]))
        )
        codec = WorkspaceEnvelopeCodec(_unb64(workspace["workspace_key"]))
        envelope = codec.seal(
            workspace_id=workspace_id,
            actor_id=str(state["actor_id"]),
            payload={
                "kind": "workspace.snapshot",
                "snapshot": service.memory.export_workspace(workspace_id),
            },
            signing_key=signing_key,
        )
        return self._request(
            "POST",
            f"{workspace['relay_url']}/workspaces/{workspace_id}/events",
            access_token=workspace["access_token"],
            json_body={"envelope": envelope.to_dict()},
        )

    def status(self, workspace_id: str = "") -> dict[str, Any]:
        state = self.state.load()
        ids = [workspace_id] if workspace_id else list(state["workspaces"])
        return {
            "actor_id": state.get("actor_id"),
            "actor_name": state.get("actor_name"),
            "workspaces": [
                {
                    "workspace_id": item,
                    "relay_url": state["workspaces"][item]["relay_url"],
                    "role": state["workspaces"][item]["role"],
                    "cursor": int(state["workspaces"][item].get("cursor") or 0),
                }
                for item in ids
                if item in state["workspaces"]
            ],
        }

    def _workspace(self, workspace_id: str) -> dict[str, Any]:
        workspace = self.state.workspace(workspace_id)
        if not workspace:
            raise RelayError("relay_workspace_not_joined")
        return workspace


class RelayCoordinator:
    def __init__(self, client: AttackGraphRelayClient) -> None:
        self.client = client
        self.last_error = ""

    @classmethod
    def from_env(cls) -> RelayCoordinator:
        path = os.getenv("ATTACKGRAPH_RELAY_STATE_PATH", ".attackgraph/relay.json")
        return cls(AttackGraphRelayClient(RelayStateStore(path)))

    def pull(self, service: AttackGraphService, engagement_id: str = "") -> int:
        if engagement_id:
            return (
                self.client.pull_workspace(service, engagement_id)
                if self.client.state.workspace(engagement_id)
                else 0
            )
        return self.client.pull_all(service)

    def push(self, service: AttackGraphService, engagement_id: str) -> dict[str, Any] | None:
        if not self.client.state.workspace(engagement_id):
            return None
        self.pull(service, engagement_id)
        return self.client.push_workspace(service, engagement_id)

    def pull_best_effort(self, service: AttackGraphService, engagement_id: str = "") -> int:
        try:
            result = self.pull(service, engagement_id)
            self.last_error = ""
            return result
        except RelayError as exc:
            self.last_error = str(exc)
            return 0

    def push_best_effort(
        self, service: AttackGraphService, engagement_id: str
    ) -> dict[str, Any] | None:
        try:
            result = self.push(service, engagement_id)
            self.last_error = ""
            return result
        except RelayError as exc:
            self.last_error = str(exc)
            return None
