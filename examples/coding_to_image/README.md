# Example: Coding Agent delegates to Image Agent

A single-developer scenario that demonstrates the full ATF flow end-to-end:

- **Agent A** ("coding"): a code-writing agent that occasionally needs an image
- **Agent B** ("image"): an image-generation agent owned by the same developer
- The two agents do not share a process or a database; they only share trust
  via ATF (Identity → Manifest → Delegation Token → Outcome → Cross-Signed Audit)

The image generation is mocked (no real model is called); the point is the
trust + audit machinery.

## How to run

From the repository root:

```bash
cd reference/py
.venv/bin/python -m examples.coding_to_image.run
```

You should see the 11-step happy path execute and, at the end, both agents'
audit logs holding byte-identical, dual-signed `delegation.completed`
records.
