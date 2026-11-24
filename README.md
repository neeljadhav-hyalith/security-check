# security-check

A Claude skill that checks an app or website you built, often with AI tools (Lovable, Bolt, Cursor, Claude Code, Replit, v0, Supabase, Firebase, Vercel), for the security holes founders leave most often. Claude reads the code and config, runs a secret scan, checks the live app only where it is safe and only on systems you own, and reports what it finds worst first, in plain words, with the fix for each. It changes nothing without your yes.

Built by Neel Jadhav, Hyalith AI. More free tools: https://hyalith.ai/resources

## Install

**Claude Code:** copy this folder into `~/.claude/skills/security-check/` (or your project's `.claude/skills/`). Open your project and ask Claude: "check my app for security holes".

**Claude.ai:** Settings > Capabilities > Skills > Upload skill, and upload a zip of this folder. Claude.ai cannot read your project folder, so upload the code as a zip or paste the files you want checked.

## How to use

1. Open your project in Claude Code.
2. Say "check my app for security holes" and name the live domain if you want live checks. Claude asks you to confirm you own it.
3. Read the report. Say which findings to fix. Claude backs up first, fixes 1 at a time and re-checks.

## Run the secret scan on its own

Needs Python 3, no other installs. Reads only. Never prints a full secret.

```
python scripts/secret_scan.py path/to/your/project --history
```

Run it on your source folder and again on your built output (`dist`, `build` or `.next`), because the built output is what visitors download. Exit code 1 means at least 1 FAIL.

## What is inside

- `SKILL.md`: the instructions Claude follows: the guardrails, the 16 checks in order of damage, the safe live checks, how to rank findings, known false alarms.
- `scripts/secret_scan.py`: finds likely exposed secrets: 20 key formats, Supabase keys decoded, database URLs, `.env` files, secret names in public env variables, source maps, and with `--history` past git commits.
- `SOURCES.md`: the incidents and documentation behind each check.

## Licence

MIT. Use it, change it, share it.
