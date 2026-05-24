"""``atf`` command-line tool.

Subcommands
-----------

* ``atf init <agent>``              — create identity + audit log
* ``atf publish <agent> --cap <c>``  — publish a capability manifest
* ``atf delegate ...``              — issue a delegation token (prints JWS)
* ``atf verify <token>``            — inspect a token, verify signature
* ``atf audit ls <agent>``          — list audit events for a local agent
* ``atf serve <agent> --port N``    — run the HTTP server (requires app config)

The CLI is intentionally minimal — it exists for ops and demo, not for
production agents (those embed the SDK directly).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import (
    Agent,
    KeyPair,
    parse_agent_uri,
    public_key_from_jwk,
    verify_token,
)
from ._b64 import b64url_decode


def _resolve(agent_id_or_pair: str) -> tuple[str, str]:
    """Accept either 'owner.name' or full 'agent://owner/name#kid'."""

    if agent_id_or_pair.startswith("agent://"):
        owner, name, _ = parse_agent_uri(agent_id_or_pair)
        return owner, name
    if "." not in agent_id_or_pair or "/" in agent_id_or_pair:
        raise click.UsageError(
            "agent identifier must be 'owner.name' or agent:// URI"
        )
    # Split at the LAST dot so 'example.com.coding' works (rarely correct, but
    # we default to last segment as name; users with multi-dot owners should
    # use the URI form).
    parts = agent_id_or_pair.rsplit(".", 1)
    return parts[0], parts[1]


@click.group()
def main() -> None:
    """agent-trust-fabric reference CLI."""


@main.command()
@click.argument("agent_id")
@click.option("--data-dir", type=click.Path(path_type=Path))
def init(agent_id: str, data_dir: Path | None) -> None:
    """Create a fresh agent identity at the given URI ('owner.name')."""

    owner, name = _resolve(agent_id)
    a = Agent.create(name=name, owner=owner, data_dir=data_dir)
    click.echo(json.dumps(a.identity.identity_document(), indent=2))


@main.command()
@click.argument("agent_id")
@click.option("--cap", "caps", multiple=True, required=True, help="capability name")
@click.option("--data-dir", type=click.Path(path_type=Path))
def publish(agent_id: str, caps: tuple[str, ...], data_dir: Path | None) -> None:
    """Publish the capability manifest for the agent."""

    owner, name = _resolve(agent_id)
    a = Agent.create(name=name, owner=owner, data_dir=data_dir)
    env = a.publish_manifest(list(caps))
    click.echo(json.dumps(env, indent=2))


@main.command()
@click.argument("agent_id")
@click.option("--to", "delegatee", required=True, help="delegatee agent URI")
@click.option("--scope", "scopes", multiple=True, required=True)
@click.option("--purpose", required=True)
@click.option("--expires-in", type=int, default=3600)
@click.option("--data-dir", type=click.Path(path_type=Path))
def delegate(
    agent_id: str,
    delegatee: str,
    scopes: tuple[str, ...],
    purpose: str,
    expires_in: int,
    data_dir: Path | None,
) -> None:
    """Issue a delegation token."""

    owner, name = _resolve(agent_id)
    a = Agent.create(name=name, owner=owner, data_dir=data_dir)
    token = a.issue_delegation(
        to=delegatee, scope=list(scopes), purpose=purpose, expires_in=expires_in
    )
    click.echo(token)


@main.command()
@click.argument("token")
@click.option(
    "--jwks-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="JWKS file containing the delegator's public key",
)
@click.option("--expected-sub", required=True)
@click.option("--scope", "scope", required=True)
def verify(token: str, jwks_file: Path, expected_sub: str, scope: str) -> None:
    """Verify a token using a JWKS file as the source of trust."""

    jwks = json.loads(jwks_file.read_text())
    pk = public_key_from_jwk(jwks["keys"][0])
    claims = verify_token(
        token,
        delegator_public_key=pk,
        expected_sub=expected_sub,
        required_scope=scope,
    )
    click.echo(json.dumps(claims.to_dict(), indent=2))


@main.group()
def audit() -> None:
    """Audit-log commands."""


@audit.command("ls")
@click.argument("agent_id")
@click.option("--data-dir", type=click.Path(path_type=Path))
@click.option("--limit", type=int, default=20)
def audit_ls(agent_id: str, data_dir: Path | None, limit: int) -> None:
    """List recent audit events for a local agent."""

    owner, name = _resolve(agent_id)
    a = Agent.create(name=name, owner=owner, data_dir=data_dir)
    events = a.audit_log.all_events()[-limit:]
    for ev in events:
        c = ev["content"]
        click.echo(
            f"{c['ts']:>10}  {c['type']:<30}  jti={c.get('token_jti'):<40}  "
            f"sigs={len(ev['signatures'])}"
        )


@main.command()
@click.argument("token")
def decode(token: str) -> None:
    """Decode (without verifying) a JWS-compact token for inspection."""

    header_b, payload_b, _ = token.split(".")
    click.echo("header:")
    click.echo(json.dumps(json.loads(b64url_decode(header_b)), indent=2))
    click.echo("payload:")
    click.echo(json.dumps(json.loads(b64url_decode(payload_b)), indent=2))


if __name__ == "__main__":
    main()
