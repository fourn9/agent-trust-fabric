"""Wire layer: HTTP server (FastAPI) and HTTP client (httpx).

The wire layer implements the 11-step happy-path delegation flow:

1. Delegator (A) builds a token (out of scope here, see :mod:`atf.agent`).
2. A posts ``/atf/v1/invoke`` to delegatee (B) with the token + payload.
3. B verifies the token, executes via a registered handler, signs the
   outcome, builds a completion event, signs the event, stores the
   pending record, and returns outcome + event-signature.
4. A verifies the outcome and the event signature, signs the event
   itself, stores the finalized record locally, and (optionally) calls
   B's ``/atf/v1/audit/cosign`` so B can finalize its record too.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx
from fastapi import FastAPI, HTTPException, Request

from .agent import Agent
from .audit import AuditEvent
from .errors import (
    ATFError,
    OutcomeInvalidSignature,
    TokenExpired,
    TokenInsufficientScope,
    TokenInvalidSignature,
    TokenNotYetValid,
    TokenReplay,
)


logger = logging.getLogger("atf.wire")


Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]


@dataclass
class HandlerSpec:
    capability: str
    schema_id: str
    handler: Handler


def build_app(agent: Agent, handlers: dict[str, HandlerSpec]) -> FastAPI:
    """Return a FastAPI app that exposes ATF endpoints for `agent`.

    `handlers` maps an action name (e.g. ``"image.generate"``) to a
    :class:`HandlerSpec` describing the required capability and how to
    execute the action.
    """

    app = FastAPI(title=f"ATF agent {agent.agent_id}")

    @app.get("/.well-known/atf/jwks.json")
    def jwks() -> dict[str, Any]:
        return agent.identity.jwks()

    @app.get("/.well-known/atf/manifest.json")
    def manifest() -> dict[str, Any]:
        if agent.manifest_envelope is None:
            raise HTTPException(status_code=404, detail="manifest not published")
        return agent.manifest_envelope

    @app.post("/atf/v1/invoke")
    async def invoke(req: Request) -> dict[str, Any]:
        token = req.headers.get("X-ATF-Token")
        if not token:
            raise HTTPException(status_code=400, detail="missing X-ATF-Token header")
        body = await req.json()
        action = body.get("payload", {}).get("action")
        if not action:
            raise HTTPException(status_code=400, detail="missing payload.action")
        spec = handlers.get(action)
        if spec is None:
            raise HTTPException(status_code=404, detail=f"unknown action {action!r}")

        try:
            claims = agent.verify_delegation(token, required_scope=spec.capability)
        except TokenExpired as e:
            raise HTTPException(status_code=401, detail=f"token.expired: {e}")
        except TokenNotYetValid as e:
            raise HTTPException(status_code=401, detail=f"token.nbf: {e}")
        except TokenInvalidSignature as e:
            raise HTTPException(status_code=401, detail=f"token.invalid_signature: {e}")
        except TokenReplay as e:
            raise HTTPException(status_code=409, detail=f"token.replay: {e}")
        except TokenInsufficientScope as e:
            raise HTTPException(status_code=403, detail=f"token.insufficient_scope: {e}")
        except ATFError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Pre-execution journal (B-only)
        agent.audit_log.append_self(
            AuditEvent(
                type="delegation.started",
                token_jti=claims.jti,
                delegator_id=claims.iss,
                delegatee_id=agent.agent_id,
                fields={"scope": claims.scope},
            ),
            keypair=agent.keypair,
            signer_id=agent.agent_id,
        )

        # Execute (handler may be sync or async)
        params = body["payload"].get("params") or {}
        try:
            result = spec.handler(params)
            if asyncio.iscoroutine(result):
                result = await result
            status = "ok"
            outcome_payload = result
            reason = None
        except Exception as e:  # noqa: BLE001
            logger.exception("handler failed")
            status = "error"
            outcome_payload = {"error": e.__class__.__name__, "message": str(e)}
            reason = str(e)

        outcome_envelope = agent.make_outcome(
            token_jti=claims.jti,
            status=status,
            payload=outcome_payload,
            schema_id=spec.schema_id,
            reason=reason,
        )

        # Build and sign the completion event (B's signature); store pending.
        event = agent.build_completion_event(
            claims=claims, outcome_envelope=outcome_envelope
        )
        my_sig = agent.audit_log.sign_only(event, keypair=agent.keypair, signer_id=agent.agent_id)
        agent.audit_log.append_pending(event, my_signature=my_sig)

        return {
            "atf_version": "0.1",
            "request_id": body.get("request_id"),
            "outcome": outcome_envelope,
            "audit_event": {"content": event.content(), "signature": my_sig},
        }

    @app.post("/atf/v1/audit/cosign")
    async def audit_cosign(req: Request) -> dict[str, Any]:
        body = await req.json()
        event_id = body["event_id"]
        peer_signature = body["signature"]
        peer_id = peer_signature["signed_by"]
        if peer_id not in agent.peers:
            raise HTTPException(status_code=400, detail=f"unknown peer {peer_id!r}")
        try:
            agent.audit_log.finalize_pending(
                event_id,
                peer_signature=peer_signature,
                peer_public_key=agent.peer(peer_id).public_key,
            )
        except ATFError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"status": "ok"}

    @app.get("/atf/v1/audit/events")
    def audit_events() -> dict[str, Any]:
        return {"events": agent.audit_log.all_events()}

    return app


# ---- Client ----


class ATFClient:
    """HTTP client for delegator (A) side of the flow."""

    def __init__(self, agent: Agent, *, timeout: float = 10.0):
        self.agent = agent
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch_jwks(self, base_url: str) -> dict[str, Any]:
        r = await self._client.get(f"{base_url}/.well-known/atf/jwks.json")
        r.raise_for_status()
        return r.json()

    async def fetch_manifest(self, base_url: str) -> dict[str, Any]:
        r = await self._client.get(f"{base_url}/.well-known/atf/manifest.json")
        r.raise_for_status()
        return r.json()

    async def invoke(
        self,
        *,
        base_url: str,
        token: str,
        payload: dict[str, Any],
        expected_schema_id: str | None = None,
        delegatee_id: str,
        cosign: bool = True,
    ) -> dict[str, Any]:
        from ._b64 import b64url_decode

        # Pull claims out of the token (for jti, scope echo, etc.)
        _, payload_b, _ = token.split(".")
        claims_dict = json.loads(b64url_decode(payload_b))

        body = {
            "atf_version": "0.1",
            "request_id": f"req_{claims_dict['jti']}",
            "payload": payload,
            "audit_uri": claims_dict.get("audit_uri"),
        }
        r = await self._client.post(
            f"{base_url}/atf/v1/invoke",
            json=body,
            headers={
                "X-ATF-Token": token,
                "Content-Type": "application/atf+json; version=0.1",
            },
        )
        if r.status_code >= 400:
            raise ATFError(f"invoke failed {r.status_code}: {r.text}")
        resp = r.json()

        # Verify outcome
        outcome_envelope = resp["outcome"]
        try:
            self.agent.verify_outcome_envelope(
                outcome_envelope,
                from_peer=delegatee_id,
                expected_schema_id=expected_schema_id,
            )
        except OutcomeInvalidSignature as e:
            # Disputed; record one-sided event
            self.agent.audit_log.append_self(
                AuditEvent(
                    type="delegation.disputed",
                    token_jti=claims_dict["jti"],
                    delegator_id=self.agent.agent_id,
                    delegatee_id=delegatee_id,
                    fields={"reason": "outcome.invalid_signature", "detail": str(e)},
                ),
                keypair=self.agent.keypair,
                signer_id=self.agent.agent_id,
            )
            raise

        # Finalize cross-signed audit event locally
        ae = resp["audit_event"]
        event_content = ae["content"]
        peer_sig = ae["signature"]
        from .audit import AuditEvent as _AE

        event = _AE.from_content(event_content)
        my_sig = self.agent.audit_log.sign_only(
            event, keypair=self.agent.keypair, signer_id=self.agent.agent_id
        )
        self.agent.audit_log.append_finalized(
            event,
            my_signature=my_sig,
            peer_signature=peer_sig,
            peer_public_key=self.agent.peer(delegatee_id).public_key,
        )

        # Push my signature back to peer so they can finalize too
        if cosign:
            try:
                await self._client.post(
                    f"{base_url}/atf/v1/audit/cosign",
                    json={"event_id": event.event_id, "signature": my_sig},
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("cosign push failed (non-fatal): %s", e)

        return resp
