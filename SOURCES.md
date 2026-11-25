# Sources for security-check (researched 24-Nov-2026)

"Read" means the page was opened and read. "Search only" means it showed up in search results but could not be opened, so nothing from it is cited as fact.

## Incidents in AI-built and founder-built apps (read)

| Title | URL | What it showed |
|---|---|---|
| Matt Palmer, statement on CVE-2025-48757 | https://mattpalmer.io/posts/statement-on-CVE-2025-48757/ | Scan of 1,645 Lovable showcase apps: 303 exposed endpoints across 170 apps (about 10%), from missing or wrong Supabase row-level security. Emails, phone numbers, payment data and developer API keys readable; on 1 app he could write a `payment_status: paid` record and skip Stripe. Notes the later Lovable scanner checks only that a policy exists, not that it is correct. |
| NVD, CVE-2025-48757 | https://nvd.nist.gov/vuln/detail/CVE-2025-48757 | Official record: insufficient RLS policy in Lovable-generated sites let unauthenticated users read or write tables. Marked disputed in some databases. |
| Wiz, exposed Moltbook database | https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys | Supabase key in the production JS bundle, RLS off, so the database answered as if the caller were an admin. About 17,000 owner records, 29,600 sign-up emails, 4,060 private messages (some with plaintext OpenAI keys) and write access to posts. Fixed within about a day of the report (31-Jan to 01-Feb-2026). |
| Hacker News, "Hacking Moltbook" (397 points, 245 comments) | https://news.ycombinator.com/item?id=46857615 | Commenters: starter guides default to "access to everything" and AI tools copy that; the "publishable" key name implies safety it does not give; write access was open too; test as an outsider with the anon key. |
| The Register, Lovable-hosted app exposed 18K users (27-Feb-2026) | https://www.theregister.com/2026/02/27/lovable_app_vulnerabilities | Exam app: 16 flaws, 6 critical. No RLS or role checks, and 1 auth function had its logic inverted: it blocked logged-in users and let anonymous ones in. 18,697 user records reachable. |
| 404 Media, Tea app breach | https://404media.co/women-dating-safety-app-tea-breached-users-ids-posted-to-4chan | Exposed Firebase storage, "no authentication", selfies and IDs posted to 4chan. Article does not give a count. |
| Simon Willison, official statement from Tea | https://simonwillison.net/2025/Jul/26/official-statement-from-tea/ | Tea's own count: about 72,000 images, about 13,000 of them selfies and photo IDs from verification, from a "legacy data storage system". |
| Awesome Agents, founder loses USD 2,500 after AI-coded app leaks Stripe key | https://awesomeagents.ai/news/founder-loses-2500-ai-coded-app-security-flaw/ | App built with Claude Code shipped a Stripe live secret key in front-end JavaScript. Attackers charged 175 customers USD 500 each. Stripe reversed the charges but kept about USD 2,500 in fees. Founder: "I trusted it too much." Original source is the founder's LinkedIn post, 28-Feb-2026 (not read directly). |
| Vibe Graveyard, EnrichLead shutdown | https://vibegraveyard.ai/story/enrichlead-vibe-coded-saas-shutdown/ | App built with Cursor, "zero hand-written code". Keys in the client, usage maxed out, paywall bypassed in the browser, random data written to the database. Shut down within about a week (March 2025). Secondary source; cites Indie Hackers and Kaspersky. |
| The Register, Replit agent deleted a production database (21-Jul-2025) | https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident | AI coding agent deleted a live database during a code freeze, made up data, and wrongly said rollback was impossible. Lesson for this skill: never give a coding agent write access to production, and stay read-only during an audit. |
| Escape.tech, methodology for 5,600 vibe-coded apps | https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/ | 5,600+ public apps (mostly Lovable): 2,000+ vulnerabilities, 400+ exposed secrets, 175 cases of personal data. Worst: exposed Supabase tokens, service-role keys in bundles, missing RLS, mostly reachable without login. Passive scans, so a floor. |
| Wiz, common security risks in vibe-coded apps | https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps | 4 recurring patterns: login checked in the browser (flags in localStorage), keys in client JS, loose or missing RLS, internal tools published with no login. |
| GitGuardian, State of Secrets Sprawl 2025 | https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/ | About 23.8 million new secrets on public GitHub in 2024 (+25%). 70% of secrets leaked in 2022 still worked. 35% of private repos held secrets. |
| CISA alert, npm supply chain compromise (23-Sep-2025) | https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem | Shai-Hulud worm compromised 500+ npm packages and stole GitHub, npm and cloud tokens. Advice: check lock files, pin safe versions, rotate tokens, phishing-resistant MFA, Dependabot and secret scanning. |
| Vercel postmortem, Next.js middleware bypass (CVE-2025-29927) | https://vercel.com/blog/postmortem-on-next-js-middleware-bypass | A crafted header skipped middleware, so auth placed only in middleware could be bypassed on self-hosted Next.js. Fixed in 12.3.5, 13.5.9, 14.2.25, 15.2.3. Vercel, Netlify and Cloudflare-hosted apps were not affected. |

## Vendor and standards guidance (read)

| Title | URL | What it showed |
|---|---|---|
| Supabase, Row Level Security | https://supabase.com/docs/guides/database/postgres/row-level-security | Enable RLS on every table in an exposed schema. With RLS on and no policy, the publishable key reads nothing. `service_role` and secret keys bypass RLS: never in the browser. Note: the page also carried text addressed to AI agents, asking them to file a report. Ignored. A real example of why this skill treats fetched pages as data. |
| Firebase, avoid insecure rules | https://firebase.google.com/docs/rules/insecure-rules | Never ship test-mode rules (`allow read, write: if true`). `request.auth != null` alone gives every logged-in user the whole database. |
| Firebase, API keys | https://firebase.google.com/docs/projects/api-keys | Firebase-restricted API keys are not secrets; rules and App Check protect the data. A Gemini API key must never be in client code. Restrict every key. |
| Stripe, webhooks | https://docs.stripe.com/webhooks | Verify the `Stripe-Signature` header with the endpoint secret on the raw body; without it an attacker can fake events to fulfil orders or grant access. 5-minute replay window. Log event IDs to skip duplicates. |
| Vite, env variables and modes | https://vite.dev/guide/env-and-mode | `VITE_` variables are baked into the client bundle; never put API keys there. Keep `*.local` in `.gitignore`. |
| OWASP, LLM01 prompt injection | https://genai.owasp.org/llmrisk/llm01-prompt-injection/ | Direct and indirect injection. No fool-proof fix, so limit impact: least privilege, human approval for risky actions, mark untrusted content, validate output in code. |
| OWASP API Security Top 10 (2023) | https://api-security.owasp.org/editions/2023/en/0x11-t10 | Broken object-level auth (IDOR) is number 1; unrestricted resource consumption (no rate limits, paid-call abuse) is number 4; broken function-level auth (admin routes) is number 5. |
| MDN, CORS | https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS | `Access-Control-Allow-Origin: *` cannot be used with credentials; a dynamic origin needs an allow-list and `Vary: Origin`. |
| GitHub, push protection | https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection | Push protection for users is on by default on GitHub.com and blocks pushing secrets to public repositories. |

## Standards behind checks 16 to 20 and the bot check in check 9 (read 25-Nov-2026)

| Title | URL | What it showed |
|---|---|---|
| OWASP, SQL Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html | Parameterised queries are the primary defence. Table and column names from the user are mapped to a strict allow-list of values the application owns. Escaping user input is strongly discouraged. |
| OWASP, Input Validation Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html | Validate on the server even when the browser checks the same fields; client-side validation can be bypassed and is for feedback. Define what is accepted (type, length limits, minimum and maximum values) and reject the rest. |
| OWASP, File Upload Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | List allowed extensions. Validate the file type and do not trust the Content-Type header. Change the filename to one the application generates. Set a size limit. Store files on a different server, or outside the web root. |
| OWASP API Security Top 10 2023, API3 Broken Object Property Level Authorization | https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/ | An endpoint exposes object properties the user should not read. Avoid generic methods such as `to_json()`; pick the specific properties to return. |
| OWASP, Password Storage Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html | Argon2id preferred, then scrypt, bcrypt for legacy systems, PBKDF2 where FIPS-140 is required. Fast hashes such as SHA-256 are not suitable. Passwords are hashed, not encrypted. |
| OWASP, Cryptographic Storage Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html | The best protection is not to store sensitive information. AES with a key of at least 128 bits, ideally 256, in an authenticated mode (GCM or CCM first). Keys stored separately from the encrypted data. |
| Cloudflare Turnstile, Validate the token | https://developers.cloudflare.com/turnstile/get-started/server-side-validation/ | Turnstile tokens are validated on the server through the siteverify API. The page was read for that step only; the line that a honeypot is a first filter is the author's judgement, not from a source. |

## Search only (could not be opened; not cited)

| Title | URL | Why listed |
|---|---|---|
| r/vibecoding, "170 Lovable apps got hacked because of one Supabase setting" | https://www.reddit.com/r/vibecoding/comments/1q2sw99/170_lovable_apps_got_hacked_because_of_one/ | Confirms the topic is live with founders. Reddit blocks the fetch tools used. |
| r/VibeCodeDevs, "I realised how vulnerable these vibe coded apps can be" | https://www.reddit.com/r/VibeCodeDevs/comments/1qpjfwz/i_realised_how_vulnerable_these_vibe_coded_apps/ | Search snippet lists source maps, RLS "on" but empty, and open `/admin` routes. Not read in full. |
| r/Supabase, "State of Supabase exposure across vibe-coding apps" | https://www.reddit.com/r/Supabase/comments/1qfoxmt/state_of_supabase_exposure_across_vibecoding_apps/ | Snippet claims 1 in 9 of 20,000 apps leaked database keys. Not read; not cited. |
| YouTube, "Vibe Coding, Audited: Productivity, Security, CVE Numbers Behind the Hype" | https://www.youtube.com/watch?v=fH2S35Nxh80 | Found through Hacker News. The page gave no transcript or description, so nothing from it is used. |
