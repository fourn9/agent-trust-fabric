"""End-to-end demo: a Coding Agent delegates an image task to an Image Agent.

Both agents are owned by the same developer (the "single-developer
multi-agent" MVP target). They live in separate data dirs, only sharing
trust via ATF.

Run from `reference/py`::

    .venv/bin/python -m examples.coding_to_image.run
"""

from __future__ import annotations

import asyncio
import socket
import sys
import tempfile
import threading
from pathlib import Path

import uvicorn

from atf import Agent, ATFClient, HandlerSpec, build_app, verify_record_signatures


GREEN = "\033[32m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def step(n: int, label: str) -> None:
    print(f"{BOLD}{n:>2}. {label}{RESET}")


def info(msg: str) -> None:
    print(f"   {DIM}{msg}{RESET}")


def ok(msg: str) -> None:
    print(f"   {GREEN}OK{RESET} {msg}")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        dir_a = base / "agent_coding"
        dir_b = base / "agent_image"
        dir_a.mkdir()
        dir_b.mkdir()

        # --- Setup ---
        step(1, "Bootstrap identities (Ed25519 keypairs, well-known URIs)")
        a = Agent.create(name="coding", owner="findy.co.jp", data_dir=dir_a, kid="1")
        b = Agent.create(name="image", owner="findy.co.jp", data_dir=dir_b, kid="1")
        info(f"A = {a.agent_id}")
        info(f"B = {b.agent_id}")
        ok("identities created")

        step(2, "Publish capability manifests")
        a.publish_manifest(["code.write", "image.generate"])
        b.publish_manifest(["image.generate"])
        info(f"A capabilities: code.write, image.generate")
        info(f"B capabilities: image.generate")
        ok("manifests signed and persisted")

        step(3, "Register peers (in production this is via well-known URIs)")
        a.register_peer(
            agent_id=b.agent_id,
            public_key=b.keypair.public_key,
            manifest_envelope=b.manifest_envelope,
        )
        b.register_peer(
            agent_id=a.agent_id,
            public_key=a.keypair.public_key,
            manifest_envelope=a.manifest_envelope,
        )
        ok("peers registered with verified manifests")

        # --- B server ---
        async def image_handler(params: dict) -> dict:
            prompt = params.get("prompt", "untitled")
            return {
                "image_url": f"https://images.example.com/{prompt.replace(' ', '-')}.png",
                "size": params.get("size", "1024x1024"),
            }

        handlers = {
            "image.generate": HandlerSpec(
                capability="image.generate",
                schema_id="image.generate.v1",
                handler=image_handler,
            )
        }
        app_b = build_app(b, handlers)
        port = _free_port()
        config = uvicorn.Config(app_b, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        # Wait for server
        for _ in range(50):
            if server.started:
                break
            await asyncio.sleep(0.05)
        info(f"B HTTP server: http://127.0.0.1:{port}")

        try:
            # --- Delegation ---
            step(4, "A issues a scoped delegation token (JWS, Ed25519, 60s TTL)")
            token = a.issue_delegation(
                to=b.agent_id,
                scope=["image.generate"],
                purpose="blog post hero image",
                constraints={"max_cost_usd": 0.50},
                expires_in=60,
            )
            info(f"token (first 40 chars): {token[:40]}...")
            ok("token issued and journaled in A's audit log")

            step(5, "A invokes B over HTTP with the token")
            client = ATFClient(a)
            try:
                resp = await client.invoke(
                    base_url=f"http://127.0.0.1:{port}",
                    token=token,
                    payload={
                        "action": "image.generate",
                        "params": {"prompt": "sunset on mars"},
                    },
                    expected_schema_id="image.generate.v1",
                    delegatee_id=b.agent_id,
                )
            finally:
                await client.aclose()

            ok("HTTP request sent")

            step(6, "(B side) verified signature, exp, sub, scope, manifest")
            ok("token accepted by B")

            step(7, "(B side) executed image.generate handler")
            outcome_content = resp["outcome"]["outcome"]
            info(f"status = {outcome_content['status']}")
            info(f"payload = {outcome_content['payload']}")

            step(8, "(B side) signed outcome and built completion audit event")
            ok(f"event_id = {resp['audit_event']['content']['event_id']}")

            step(9, "(A side) verified outcome signature, schema, hash")
            ok("outcome envelope verified")

            step(10, "(A side) co-signed the audit event, stored finalized")
            event_id = resp["audit_event"]["content"]["event_id"]
            a_record = a.audit_log.get(event_id)
            assert a_record is not None
            assert len(a_record["signatures"]) == 2
            ok(f"A's record has {len(a_record['signatures'])} signatures")

            step(11, "(A side) pushed A's signature back to B via /atf/v1/audit/cosign")
            # Wait briefly for the async push to land
            for _ in range(20):
                if b.audit_log.pending_peer_count() == 0:
                    break
                await asyncio.sleep(0.05)
            b_record = b.audit_log.get(event_id)
            assert b_record is not None
            assert len(b_record["signatures"]) == 2
            ok(f"B's record has {len(b_record['signatures'])} signatures")

            # --- Verification ---
            print()
            step(0, "Cross-check: A and B hold byte-identical, dual-signed records")
            assert a_record["content"] == b_record["content"], "content mismatch!"
            verify_record_signatures(
                a_record,
                public_keys_by_signer={
                    a.agent_id: a.keypair.public_key,
                    b.agent_id: b.keypair.public_key,
                },
            )
            verify_record_signatures(
                b_record,
                public_keys_by_signer={
                    a.agent_id: a.keypair.public_key,
                    b.agent_id: b.keypair.public_key,
                },
            )
            ok("third-party verification of both records succeeded")

            print()
            print(f"{BOLD}{GREEN}✓ End-to-end delegation completed.{RESET}")
            print(f"{DIM}A's audit log: {len(a.audit_log.all_events())} events. "
                  f"B's audit log: {len(b.audit_log.all_events())} events.{RESET}")
            return 0

        finally:
            server.should_exit = True
            for _ in range(20):
                if not t.is_alive():
                    break
                await asyncio.sleep(0.05)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
