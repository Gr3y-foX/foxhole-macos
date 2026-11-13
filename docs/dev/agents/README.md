# Subagent definitions (copies)

Copies of the Claude Code subagents used on this repo. The live files sit in the main checkout's
`.claude/agents/`, which is never committed (repo rule). These copies let a session without the Mac
(GitHub web, a cloud session) read the team setup, and let a new machine recreate it:

```bash
mkdir -p .claude/agents && cp docs/dev/agents/{coder,docs-scout,github-ops}.md .claude/agents/
```

| Agent | Model | Job |
|---|---|---|
| `coder.md` | Sonnet | code, tests, debugging; reports in caveman style; no git writes, no host system commands |
| `docs-scout.md` | Haiku | read docs, git history and logs, write reports, bullet summaries; read-only on code |
| `github-ops.md` | Haiku | git/GitHub commands exactly as ordered (fast-forward, push); never decides what to change |

Copied 2026-11-13. Only change against the live files: `github-ops.md` names the repo root
instead of an absolute home-directory path. If you edit an agent, update both places.
