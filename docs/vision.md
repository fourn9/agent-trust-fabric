# Vision: a neutral substrate for agent collaboration

## The bet

By 2028, AI agents will routinely act outside the boundary of the developer
who built them — calling other agents, accessing other teams' data, taking
actions that span vendors. The internet that connects them needs the
equivalent of TLS, OAuth, and Sigstore — three concepts that humans solved
incrementally over three decades, that the agent world needs in three years.

ATF is one attempt at that substrate. It will not be the only one, and it
may not be the one that wins. But the gap is real:

- A2A and MCP define the wires, not the trust.
- LangGraph / CrewAI / Microsoft Agent Framework define orchestration
  within one developer's control, not across.
- Salesforce Agent Fabric, ServiceNow Agent Fabric, etc. are vendor-bound.
- Solace Agent Mesh is OSS but skews toward routing, not delegation/audit
  with cryptographic verifiability.

The neutral, federated, audit-first slice is open. ATF claims it.

## The shape of the substrate

A ten-layer stack (see [design doc §2.1](./specs/2026-05-23-atf-design.md)).
The MVP is five layers. Each subsequent layer is its own spec, its own
implementation milestone, its own conformance test set. Layered shipping is
non-negotiable — anything that asks "let's build the whole substrate at
once" is rejected by the design criteria.

## Where this product wins

1. **For a single developer with multiple agents**, ATF gives them a real
   delegation / audit framework instead of ad-hoc try/except.
2. **For an organization with multi-team agents**, ATF makes cross-team
   access controllable and provable.
3. **For competitor-vendor scenarios (the eventual prize)**, ATF is the
   only neutral place to land trust.

## Where this product does not try to win

- Not the wire (A2A wins, MCP wins).
- Not the orchestrator (CrewAI / LangGraph / Agent Framework win).
- Not the LLM observability stack (Langfuse / Braintrust / etc. win).
- Not domain-specific verification (left to domain).

## Relationship to harness engineering

"Agent harness engineering" (Addy Osmani) is about making **one agent good**:
the scaffolding around a model — system prompt, tools, context management,
and subagents. It is a *vertical* concern, living entirely inside the
boundary of a single agent.

ATF is a *horizontal* concern. It is about what happens at the **seam
between agents** — trust, scoped delegation, outcome verification, and
audit. The two axes are orthogonal: harness = depth (one agent's internals),
ATF = breadth (between agents). They are **not the same thing, and not
unrelated** — they meet at exactly one place: the **trust boundary**.

A harness's `subagents` and `tools` pillars handle delegation *within the
same trust domain* (one process, one owner, one security boundary). The
moment a harness wants to reach an agent it does **not** control — a
different vendor, a different developer, a different security boundary — it
crosses out of "harness concern" and into "ATF concern." In that sense ATF
is the **standardized protocol for the cross-domain case of the harness's
subagent/tool pillars**.

```
Harness spawns a subagent
  ├─ same trust domain (fully controlled)        → harness handles it; ATF not needed
  └─ crosses trust domains (other vendor/owner)   → ATF kicks in
```

Concretely: today's Claude Code subagents and Agent Teams are same-process,
same-trust-domain — pure harness, no ATF required. Delegating a deploy to
*another company's* agent is where the harness runs out and ATF begins.

The two also share design DNA. ATF borrows harness engineering's
"the bottleneck is verification, not generation" principle (design
principle #3; L6 Outcome Verification embodies it) and its
Planner–Worker–Judge structure (the issue → execute → verify loop). The
scopes differ; the philosophy is the same.

Analogy: harness engineering is *how you grow a capable employee* (skills,
tools, knowledge, assistants). ATF is *how employees from different
companies do business safely* (contracts, identity checks, scoped
authority, audit). Different things — but a capable employee operating
across company boundaries needs both.

## Adoption hypothesis

The first 10 users are the same developer running multiple agents and using
ATF for internal sanity / audit. The next 100 are organizations that need
cross-team delegation to be auditable. The next 1000 are the first cross-
vendor pioneers. We do not chase the 1000 case until the 10 case is solid.

## Governance hypothesis

Specs are versioned independently of any single implementation. The
reference implementation is Apache 2.0. If ATF reaches a critical mass, the
spec is offered to a neutral standards body (likely Linux Foundation's
Agentic AI Foundation, which already houses A2A and MCP). Until then,
governance is informal and the design criteria in
[ADR-0001](../decisions/0001-design-criteria.md) bind decisions.
