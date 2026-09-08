from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _from_b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class IdentityError(RuntimeError):
    pass


class IdentityStore:
    """Local control-plane identity store shared by the dashboard and MCP processes."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    webauthn_user_id BLOB NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS passkeys (
                    credential_id BLOB PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL,
                    transports TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    backed_up INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS browser_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    owner_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    token_hint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS memberships (
                    engagement_id TEXT NOT NULL,
                    principal_type TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (engagement_id, principal_type, principal_id)
                );
                CREATE TABLE IF NOT EXISTS invites (
                    invite_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    engagement_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS passkey_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    challenge BLOB NOT NULL,
                    metadata TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS h3retik_session_bindings (
                    binding_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    lane TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    attached_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (engagement_id, session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_memberships_principal
                    ON memberships(principal_type, principal_id, engagement_id);
                CREATE INDEX IF NOT EXISTS idx_agents_owner
                    ON agents(owner_user_id, status);
                CREATE INDEX IF NOT EXISTS idx_invites_engagement
                    ON invites(engagement_id, used_at, expires_at);
                CREATE INDEX IF NOT EXISTS idx_h3retik_bindings_engagement
                    ON h3retik_session_bindings(engagement_id, status);
                """
            )
            binding_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(h3retik_session_bindings)")
            }
            if "lane" not in binding_columns:
                connection.execute(
                    "ALTER TABLE h3retik_session_bindings ADD COLUMN lane TEXT NOT NULL DEFAULT ''"
                )
            connection.execute("PRAGMA optimize")

    def passkey_count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0])

    def user(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT user_id, display_name, created_at FROM users WHERE user_id=?",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def begin_passkey_registration(
        self,
        *,
        display_name: str,
        rp_id: str,
        rp_name: str,
        invite_token: str = "",
        current_user_id: str = "",
    ) -> dict[str, Any]:
        display_name = display_name.strip()[:80]
        if not display_name:
            raise IdentityError("display_name_required")
        invite = self._valid_invite(invite_token) if invite_token else None
        if self.passkey_count() and not invite and not current_user_id:
            raise PermissionError("invite_or_authenticated_user_required")

        with self._connect() as connection:
            current = (
                connection.execute(
                    "SELECT user_id, webauthn_user_id FROM users WHERE user_id=?",
                    (current_user_id,),
                ).fetchone()
                if current_user_id
                else None
            )
            user_id = str(current["user_id"]) if current else f"usr_{uuid.uuid4().hex[:12]}"
            user_handle = bytes(current["webauthn_user_id"]) if current else secrets.token_bytes(32)
            credentials = connection.execute(
                "SELECT credential_id FROM passkeys WHERE user_id=?", (user_id,)
            ).fetchall()

        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=user_handle,
            user_name=display_name,
            user_display_name=display_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
                for row in credentials
            ],
        )
        challenge_id = f"chl_{uuid.uuid4().hex}"
        metadata = {
            "user_id": user_id,
            "user_handle": _b64(user_handle),
            "display_name": display_name,
            "invite_id": str(invite["invite_id"]) if invite else "",
        }
        self._save_challenge(challenge_id, "register", options.challenge, metadata)
        return {"challenge_id": challenge_id, "publicKey": json.loads(options_to_json(options))}

    def finish_passkey_registration(
        self,
        *,
        challenge_id: str,
        credential: dict[str, Any],
        expected_rp_id: str,
        expected_origin: str,
    ) -> tuple[dict[str, Any], str]:
        challenge = self._take_challenge(challenge_id, "register")
        metadata = challenge["metadata"]
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge["challenge"],
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            require_user_verification=True,
        )
        user_id = str(metadata["user_id"])
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO users(user_id, display_name, webauthn_user_id, created_at)
                VALUES(?,?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name
                """,
                (
                    user_id,
                    str(metadata["display_name"]),
                    _from_b64(str(metadata["user_handle"])),
                    _iso(),
                ),
            )
            response = credential.get("response") or {}
            device_type = getattr(verification.credential_device_type, "value", None)
            connection.execute(
                """
                INSERT INTO passkeys(
                    credential_id, user_id, public_key, sign_count, transports,
                    device_type, backed_up, created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    verification.credential_id,
                    user_id,
                    verification.credential_public_key,
                    verification.sign_count,
                    json.dumps(response.get("transports") or []),
                    str(device_type or verification.credential_device_type),
                    int(verification.credential_backed_up),
                    _iso(),
                ),
            )
            invite_id = str(metadata.get("invite_id") or "")
            if invite_id:
                invite = connection.execute(
                    """
                    SELECT engagement_id, role, used_at, expires_at
                    FROM invites WHERE invite_id=?
                    """,
                    (invite_id,),
                ).fetchone()
                invite_expired = invite and datetime.fromisoformat(invite["expires_at"]) <= _now()
                if not invite or invite["used_at"] or invite_expired:
                    raise IdentityError("invite_expired_or_used")
                connection.execute(
                    "UPDATE invites SET used_at=? WHERE invite_id=?", (_iso(), invite_id)
                )
                connection.execute(
                    """
                    INSERT OR REPLACE INTO memberships(
                        engagement_id, principal_type, principal_id, role, created_at
                    ) VALUES(?,?,?,?,?)
                    """,
                    (invite["engagement_id"], "human", user_id, invite["role"], _iso()),
                )
        token = self.create_browser_session(user_id)
        return self.user(user_id) or {"user_id": user_id}, token

    def begin_passkey_authentication(self, *, rp_id: str) -> dict[str, Any]:
        if not self.passkey_count():
            raise IdentityError("passkey_setup_required")
        options = generate_authentication_options(
            rp_id=rp_id,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        challenge_id = f"chl_{uuid.uuid4().hex}"
        self._save_challenge(challenge_id, "authenticate", options.challenge, {})
        return {"challenge_id": challenge_id, "publicKey": json.loads(options_to_json(options))}

    def finish_passkey_authentication(
        self,
        *,
        challenge_id: str,
        credential: dict[str, Any],
        expected_rp_id: str,
        expected_origin: str,
    ) -> tuple[dict[str, Any], str]:
        challenge = self._take_challenge(challenge_id, "authenticate")
        credential_id = base64url_to_bytes(str(credential.get("id") or ""))
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT p.user_id, p.public_key, p.sign_count, u.display_name, u.created_at
                FROM passkeys p JOIN users u ON u.user_id=p.user_id
                WHERE p.credential_id=?
                """,
                (credential_id,),
            ).fetchone()
        if not row:
            raise PermissionError("unknown_passkey")
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge["challenge"],
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
            require_user_verification=True,
        )
        with self._connect() as connection:
            connection.execute(
                "UPDATE passkeys SET sign_count=? WHERE credential_id=?",
                (verification.new_sign_count, credential_id),
            )
        user = {
            "user_id": str(row["user_id"]),
            "display_name": str(row["display_name"]),
            "created_at": str(row["created_at"]),
        }
        return user, self.create_browser_session(user["user_id"])

    def create_browser_session(self, user_id: str, hours: int = 12) -> str:
        token = f"atk_session_{secrets.token_urlsafe(32)}"
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO browser_sessions(token_hash,user_id,expires_at,created_at)
                VALUES(?,?,?,?)
                """,
                (_hash_secret(token), user_id, _iso(_now() + timedelta(hours=hours)), _iso()),
            )
        return token

    def browser_user(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT u.user_id, u.display_name, u.created_at, s.expires_at
                FROM browser_sessions s JOIN users u ON u.user_id=s.user_id
                WHERE s.token_hash=?
                """,
                (_hash_secret(token),),
            ).fetchone()
            if not row or datetime.fromisoformat(row["expires_at"]) <= _now():
                return None
        return {key: row[key] for key in ("user_id", "display_name", "created_at")}

    def revoke_browser_session(self, token: str) -> None:
        if token:
            with self._connect() as connection:
                connection.execute(
                    "DELETE FROM browser_sessions WHERE token_hash=?", (_hash_secret(token),)
                )

    def create_agent(self, *, owner_user_id: str, name: str, engagement_id: str) -> dict[str, Any]:
        name = name.strip()[:80]
        if not name:
            raise IdentityError("agent_name_required")
        agent_id = f"agt_{uuid.uuid4().hex[:12]}"
        token = f"atk_agent_{secrets.token_urlsafe(32)}"
        now = _iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agents(
                    agent_id, owner_user_id, name, token_hash, token_hint, status, created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    agent_id,
                    owner_user_id or None,
                    name,
                    _hash_secret(token),
                    token[-6:],
                    "active",
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO memberships(
                    engagement_id, principal_type, principal_id, role, created_at
                ) VALUES(?,?,?,?,?)
                """,
                (engagement_id, "agent", agent_id, "operator", now),
            )
        return {
            "agent_id": agent_id,
            "name": name,
            "status": "active",
            "engagement_id": engagement_id,
            "token": token,
            "token_hint": token[-6:],
            "created_at": now,
        }

    def authenticate_agent(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT agent_id, owner_user_id, name, status, created_at, last_seen_at
                FROM agents WHERE token_hash=?
                """,
                (_hash_secret(token),),
            ).fetchone()
            if not row or row["status"] != "active":
                return None
            connection.execute(
                "UPDATE agents SET last_seen_at=? WHERE agent_id=?", (_iso(), row["agent_id"])
            )
        return dict(row)

    def list_agents(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT a.agent_id, a.name, a.status, a.token_hint, a.created_at,
                       a.last_seen_at, m.role
                FROM memberships m JOIN agents a ON a.agent_id=m.principal_id
                WHERE m.engagement_id=? AND m.principal_type='agent'
                ORDER BY a.created_at
                """,
                (engagement_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_agent(self, agent_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE agents SET status='revoked' WHERE agent_id=?", (agent_id,))

    def add_membership(
        self, engagement_id: str, principal_type: str, principal_id: str, role: str
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO memberships(
                    engagement_id, principal_type, principal_id, role, created_at
                ) VALUES(?,?,?,?,?)
                """,
                (engagement_id, principal_type, principal_id, role, _iso()),
            )

    def can_access(self, engagement_id: str, principal_type: str, principal_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM memberships
                WHERE engagement_id=? AND principal_type=? AND principal_id=?
                """,
                (engagement_id, principal_type, principal_id),
            ).fetchone()
        return row is not None

    def membership_role(
        self, engagement_id: str, principal_type: str, principal_id: str
    ) -> str:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT role FROM memberships
                WHERE engagement_id=? AND principal_type=? AND principal_id=?
                """,
                (engagement_id, principal_type, principal_id),
            ).fetchone()
        return str(row["role"]) if row else ""

    def engagement_ids_for(self, principal_type: str, principal_id: str) -> set[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT engagement_id FROM memberships WHERE principal_type=? AND principal_id=?",
                (principal_type, principal_id),
            ).fetchall()
        return {str(row["engagement_id"]) for row in rows}

    def list_members(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            humans = connection.execute(
                """
                SELECT u.user_id AS principal_id, u.display_name AS name, m.role
                FROM memberships m JOIN users u ON u.user_id=m.principal_id
                WHERE m.engagement_id=? AND m.principal_type='human'
                """,
                (engagement_id,),
            ).fetchall()
            agents = connection.execute(
                """
                SELECT a.agent_id AS principal_id, a.name, m.role, a.status, a.last_seen_at
                FROM memberships m JOIN agents a ON a.agent_id=m.principal_id
                WHERE m.engagement_id=? AND m.principal_type='agent'
                """,
                (engagement_id,),
            ).fetchall()
        return [
            {"principal_type": "human", **dict(row)} for row in humans
        ] + [{"principal_type": "agent", **dict(row)} for row in agents]

    def create_invite(
        self,
        *,
        created_by: str,
        engagement_id: str,
        role: str = "operator",
        hours: int = 24,
    ) -> dict[str, Any]:
        if role not in {"operator", "viewer"}:
            raise IdentityError("invalid_invite_role")
        token = f"atk_invite_{secrets.token_urlsafe(24)}"
        invite_id = f"inv_{uuid.uuid4().hex[:12]}"
        expires_at = _iso(_now() + timedelta(hours=max(1, min(hours, 168))))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO invites(
                    invite_id, token_hash, engagement_id, role, created_by,
                    expires_at, created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    invite_id,
                    _hash_secret(token),
                    engagement_id,
                    role,
                    created_by,
                    expires_at,
                    _iso(),
                ),
            )
        return {
            "invite_id": invite_id,
            "token": token,
            "engagement_id": engagement_id,
            "role": role,
            "expires_at": expires_at,
        }

    def _valid_invite(self, token: str) -> sqlite3.Row:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM invites WHERE token_hash=?", (_hash_secret(token),)
            ).fetchone()
        if not row or row["used_at"] or datetime.fromisoformat(row["expires_at"]) <= _now():
            raise PermissionError("invite_expired_or_used")
        return row

    def bind_h3retik_session(
        self,
        *,
        engagement_id: str,
        session_id: str,
        label: str,
        attached_by: str,
        lane: str = "",
    ) -> dict[str, Any]:
        session_id = session_id.strip()[:160]
        label = label.strip()[:80] or "H3RETIK session"
        lane = lane.strip()[:64]
        if not session_id:
            raise IdentityError("session_id_required")
        binding_id = f"h3b_{uuid.uuid4().hex[:12]}"
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO h3retik_session_bindings(
                    binding_id, engagement_id, session_id, label, lane,
                    status, attached_by, created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(engagement_id, session_id) DO UPDATE SET
                    label=excluded.label, lane=excluded.lane, status='active'
                """,
                (binding_id, engagement_id, session_id, label, lane, "active", attached_by, _iso()),
            )
            row = connection.execute(
                "SELECT * FROM h3retik_session_bindings WHERE engagement_id=? AND session_id=?",
                (engagement_id, session_id),
            ).fetchone()
        return dict(row)

    def list_h3retik_sessions(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT binding_id, engagement_id, session_id, label, lane, status, created_at
                FROM h3retik_session_bindings WHERE engagement_id=? ORDER BY created_at
                """,
                (engagement_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _save_challenge(
        self, challenge_id: str, kind: str, challenge: bytes, metadata: dict[str, Any]
    ) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM passkey_challenges WHERE expires_at <= ?", (_iso(),))
            connection.execute(
                """
                INSERT INTO passkey_challenges(
                    challenge_id, kind, challenge, metadata, expires_at, created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    challenge_id,
                    kind,
                    challenge,
                    json.dumps(metadata),
                    _iso(_now() + timedelta(minutes=5)),
                    _iso(),
                ),
            )

    def _take_challenge(self, challenge_id: str, kind: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM passkey_challenges WHERE challenge_id=? AND kind=?",
                (challenge_id, kind),
            ).fetchone()
            connection.execute(
                "DELETE FROM passkey_challenges WHERE challenge_id=?", (challenge_id,)
            )
        if not row or datetime.fromisoformat(row["expires_at"]) <= _now():
            raise IdentityError("challenge_expired_or_missing")
        return {"challenge": bytes(row["challenge"]), "metadata": json.loads(row["metadata"])}
