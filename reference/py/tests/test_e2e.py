"""E2E test: full 11-step delegation flow via HTTP (FastAPI + httpx)."""

import asyncio
import socket
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import uvicorn

from atf import (
    Agent,
    ATFClient,
    AuditLog,
    HandlerSpec,
    build_app,
    verify_record_signatures,
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ServerThread:
    """Run uvicorn in a thread for a single test."""

    def __init__(self, app, port: int):
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(config)
        import threading

        self.thread = threading.Thread(target=self.server.run, daemon=True)

    async def start(self) -> None:
        self.thread.start()
        # Wait for server to be ready
        for _ in range(100):
            if self.server.started:
                return
            await asyncio.sleep(0.05)
        raise RuntimeError("server failed to start")

    async def stop(self) -> None:
        self.server.should_exit = True
        for _ in range(50):
            if not self.thread.is_alive():
                return
            await asyncio.sleep(0.05)


@contextmanager
def _tmpdirs(tmp_path: Path) -> Iterator[tuple[Path, Path]]:
    a = tmp_path / "agent_a"
    b = tmp_path / "agent_b"
    a.mkdir()
    b.mkdir()
    yield a, b


async def test_full_delegation_flow(tmp_path: Path):
    with _tmpdirs(tmp_path) as (dir_a, dir_b):
        # 1-2. Bootstrap + publish manifests
        a = Agent.create(name="coding", owner="findy.co.jp", data_dir=dir_a, kid="1")
        b = Agent.create(name="image", owner="findy.co.jp", data_dir=dir_b, kid="1")
        a.publish_manifest(["code.write", "image.generate"])
        b.publish_manifest(["image.generate"])

        # Register peers (in real life: HTTP fetch from well-known URI)
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

        # Set up B's server
        async def image_handler(params: dict) -> dict:
            return {
                "image_url": f"https://example.com/{params.get('prompt', 'x')}.png",
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
        server = _ServerThread(app_b, port)
        await server.start()

        try:
            # 3. A resolves B (already registered)
            # 4. A issues token
            token = a.issue_delegation(
                to=b.agent_id,
                scope=["image.generate"],
                purpose="blog illustration",
                expires_in=60,
            )

            # 5-10. Invoke + auto cross-sign
            client = ATFClient(a)
            try:
                resp = await client.invoke(
                    base_url=f"http://127.0.0.1:{port}",
                    token=token,
                    payload={
                        "action": "image.generate",
                        "params": {"prompt": "sunset"},
                    },
                    expected_schema_id="image.generate.v1",
                    delegatee_id=b.agent_id,
                )
            finally:
                await client.aclose()

            assert resp["outcome"]["outcome"]["status"] == "ok"
            assert "image_url" in resp["outcome"]["outcome"]["payload"]
            event_id = resp["audit_event"]["content"]["event_id"]

            # A side: event is fully cross-signed
            a_record = a.audit_log.get(event_id)
            assert a_record is not None
            assert len(a_record["signatures"]) == 2
            verify_record_signatures(
                a_record,
                public_keys_by_signer={
                    a.agent_id: a.keypair.public_key,
                    b.agent_id: b.keypair.public_key,
                },
            )

            # Allow cosign push to land
            await asyncio.sleep(0.2)

            # B side: should also be finalized now
            b_record = b.audit_log.get(event_id)
            assert b_record is not None
            assert len(b_record["signatures"]) == 2
            assert b.audit_log.pending_peer_count() == 0

            # Cross-check: contents are byte-identical
            assert a_record["content"] == b_record["content"]

        finally:
            await server.stop()
