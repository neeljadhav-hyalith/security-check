#!/usr/bin/env python3
"""secret_scan: find likely exposed secrets in a project folder, worst first.

Usage:
  python secret_scan.py <project_folder> [--history] [--include-deps] [--max-mb 5]

Looks for:
  - known key formats (Stripe, AWS, OpenAI, Anthropic, GitHub, Slack, SendGrid, Google, Supabase and more)
  - Supabase keys decoded: a service_role key is an admin key, an anon key is public by design
  - database URLs with a password inside
  - private key blocks and cloud service-account files
  - .env files, whether git ignores them, and whether they sit in a folder the site serves
  - secret-looking names in public env prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, PUBLIC_)
  - source maps shipped with the built site
  - with --history: secrets in past git commits (needs git on the PATH)

Never prints a full secret. Values are masked to the first 4 and last 2 characters.
Reads only. Changes nothing. Exit code 1 if anything FAILs.
MIT licence. Built by Neel Jadhav, Hyalith AI (hyalith.ai/resources)."""
import argparse, base64, json, os, re, subprocess, sys

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache",
             ".tox", ".idea", ".vscode", "vendor", "bower_components", ".terraform", ".gradle", "Pods"}
SERVED_DIRS = {"public", "static", "dist", "build", "out", ".next", "www", "assets", "_site", ".output", ".vercel"}
FRONT_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm", ".astro"}
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot",
           ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mov", ".mp3", ".wav", ".psd", ".sqlite", ".db", ".exe", ".dll", ".so"}
PUBLIC_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)"
PLACEHOLDER = re.compile(r"(x{4,}|\*{4,}|your[_-]?|example|placeholder|changeme|dummy|sample|<[^>]*>|\.\.\.|replace[_-]?me|fake|redacted)", re.I)

# (status, label, regex, why). Group 1, if present, is the value to mask.
PATTERNS = [
    ("FAIL", "Private key block", r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)",
     "A private key gives full access to whatever it signs for."),
    ("FAIL", "Stripe live secret key", r"\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})",
     "Anyone holding it can charge, refund and read your customers."),
    ("WARN", "Stripe test secret key", r"\b((?:sk|rk)_test_[0-9a-zA-Z]{20,})",
     "Test mode only, but it shows where a live key would end up. Keep it server-side."),
    ("FAIL", "Stripe webhook signing secret", r"\b(whsec_[0-9a-zA-Z]{20,})",
     "Lets anyone forge 'payment succeeded' events to your app."),
    ("FAIL", "AWS access key", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
     "Cloud account access. Bills run up within hours once found."),
    ("FAIL", "Anthropic API key", r"\b(sk-ant-[0-9A-Za-z_\-]{20,})",
     "Anyone can run models on your bill."),
    ("FAIL", "OpenAI API key", r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|sk-proj-[A-Za-z0-9_\-]{40,})",
     "Anyone can run models on your bill."),
    ("FAIL", "GitHub token", r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{60,})",
     "Read or write access to your code, often to every repository."),
    ("FAIL", "Slack token", r"\b(xox[abposr]-[0-9A-Za-z\-]{10,})",
     "Read and post in your workspace."),
    ("FAIL", "Slack webhook URL", r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})",
     "Anyone can post into your channel."),
    ("FAIL", "SendGrid API key", r"\b(SG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,})",
     "Anyone can send email as your domain."),
    ("FAIL", "Twilio API key", r"\b(SK[0-9a-fA-F]{32})\b",
     "Anyone can send SMS and calls on your bill."),
    ("FAIL", "Resend API key", r"\b(re_[0-9A-Za-z]{8,}_[0-9A-Za-z]{16,})",
     "Anyone can send email as your domain."),
    ("FAIL", "Supabase secret key", r"\b(sb_secret_[0-9A-Za-z_\-]{20,})",
     "Admin key. It skips every row-level security rule."),
    ("INFO", "Supabase publishable key", r"\b(sb_publishable_[0-9A-Za-z_\-]{20,})",
     "Public by design. Safe only if row-level security is on for every table."),
    ("FAIL", "Database URL with password", r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s/'\"]+:[^@\s'\"]{3,}@[^\s'\"]+)",
     "Direct access to your database, past every app check."),
    ("FAIL", "Google service-account key", r"(\"type\"\s*:\s*\"service_account\")",
     "Full access to the cloud project it belongs to."),
    ("WARN", "Google API key", r"\b(AIza[0-9A-Za-z_\-]{35})",
     "Fine in a Firebase config if restricted to Firebase APIs. A Gemini or unrestricted Maps key here is a bill."),
    ("WARN", "Mailchimp API key", r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
     "Read and email your whole list."),
    ("WARN", "Hugging Face token", r"\b(hf_[0-9A-Za-z]{30,})",
     "Access to your models and paid inference."),
]
JWT = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})")
GENERIC = re.compile(r"""(?i)\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|APIKEY|ACCESS_TOKEN|AUTH_TOKEN|SERVICE_ROLE|CLIENT_SECRET)[A-Z0-9_]*)\b["']?\s*[:=]\s*["']([^"'\s]{12,})["']""")
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
PUBLIC_SECRET = re.compile(PUBLIC_PREFIX + r"[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|ADMIN)[A-Z0-9_]*")

rows, seen, envs = [], set(), [0]

def mask(v):
    v = v.strip()
    m = re.match(r"([a-z+]+://[^:/]+:)([^@]+)(@[^/:]+)", v)
    if m:   # database URL: keep scheme, user and host, hide the password
        return f"{m.group(1)}****{m.group(3)}"
    if len(v) <= 10:
        return "*" * len(v)
    return f"{v[:4]}...{v[-2:]} ({len(v)} chars)"

def count(filled):
    return f"{len(filled)} value" + ("" if len(filled) == 1 else "s")

def rec(status, where, finding, value="", why=""):
    key = (status, where, finding, value)
    if key not in seen:
        seen.add(key)
        rows.append((status, where, finding, value, why))

def jwt_role(tok):
    try:
        part = tok.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part))
        return data.get("role"), data.get("iss", "")
    except Exception:
        return None, ""

def is_served(rel):
    parts = rel.replace("\\", "/").split("/")
    return any(p in SERVED_DIRS for p in parts[:-1])

def is_front(rel):
    ext = os.path.splitext(rel)[1].lower()
    return ext in FRONT_EXT and not re.search(r"(^|/)(server|api|functions|supabase/functions|backend|scripts)/", rel.replace("\\", "/"))

def scan_text(text, rel, where_prefix=""):
    front = is_front(rel) or is_served(rel)
    loc_suffix = " (served to visitors)" if is_served(rel) else (" (front-end code)" if front else "")
    for n, line in enumerate(text.splitlines(), 1):
        line_chunks = [line]
        where = f"{where_prefix}{rel}:{n}"
        for chunk in line_chunks:
            for status, label, pat, why in PATTERNS:
                for m in re.finditer(pat, chunk):
                    val = m.group(1)
                    if status != "INFO" and PLACEHOLDER.search(val):
                        continue
                    rec(status, where + loc_suffix, label, mask(val), why)
            for m in JWT.finditer(chunk):
                role, iss = jwt_role(m.group(1))
                if role == "service_role":
                    rec("FAIL", where + loc_suffix, "Supabase service_role key", mask(m.group(1)),
                        "Admin key. It skips every row-level security rule. Rotate it now.")
                elif role == "anon":
                    rec("INFO", where + loc_suffix, "Supabase anon key", mask(m.group(1)),
                        "Public by design. Safe only if row-level security is on for every table.")
                elif role is not None or iss:
                    rec("WARN", where + loc_suffix, "Signed token (JWT) in code", mask(m.group(1)),
                        "Check what it grants and whether it expires.")
            for m in GENERIC.finditer(chunk):
                name, val = m.group(1), m.group(2)
                if PLACEHOLDER.search(val) or val.startswith(("process.env", "import.meta", "os.environ", "${", "{{")):
                    continue
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", val) and not re.search(r"\d", val):
                    continue   # looks like a variable name, not a value
                rec("FAIL" if front else "WARN", where + loc_suffix, f"Hard-coded {name}", mask(val),
                    "A secret written into the code travels with every copy of it." + (" This file reaches the browser." if front else ""))
            for m in PUBLIC_SECRET.finditer(chunk):
                rec("FAIL", where, f"Secret in a public variable: {m.group(0)}", "",
                    "Public prefixes are built into the browser bundle. This name says it should never be there.")

def gitignored(root, rel):
    try:
        r = subprocess.run(["git", "-C", root, "check-ignore", "-q", rel], capture_output=True, timeout=10)
        if r.returncode in (0, 1):
            return r.returncode == 0
    except Exception:
        pass
    gi = os.path.join(root, ".gitignore")
    if os.path.exists(gi):
        pats = [l.strip() for l in open(gi, encoding="utf-8", errors="replace") if l.strip() and not l.startswith("#")]
        name = os.path.basename(rel)
        return any(p.rstrip("/") in (name, ".env", ".env*", ".env.*", "*.env", ".env.local", "*.local") and
                   (p.rstrip("/") == name or name.startswith(".env")) for p in pats)
    return None

def git_tracked(root, rel):
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", rel], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return None

def check_env_file(root, rel, text):
    name = os.path.basename(rel)
    example = re.search(r"\.(example|sample|template|dist|defaults?)$", name, re.I)
    filled = []
    for line in text.splitlines():
        m = ENV_LINE.match(line)
        if m and m.group(2).strip().strip("'\"") and not PLACEHOLDER.search(m.group(2)):
            filled.append(m.group(1))
    if example:
        if filled:
            secretish = [k for k in filled if re.search(r"SECRET|KEY|TOKEN|PASSWORD|DATABASE_URL", k, re.I)]
            if secretish:
                rec("WARN", rel, "Example env file holds real-looking values", ", ".join(secretish[:4]),
                    "Example files are meant to be committed. Check these are placeholders.")
        return
    if is_served(rel):
        rec("FAIL", rel, ".env file inside a served folder", count(filled),
            "Anyone can download it from your site at /" + name + ".")
    tracked = git_tracked(root, rel) if os.path.isdir(os.path.join(root, ".git")) else None
    if tracked:
        rec("FAIL", rel, ".env file committed to git", count(filled),
            "Every copy of the repository carries it. Rotate the keys, then remove it from history.")
    else:
        ign = gitignored(root, rel)
        if ign is False:
            rec("WARN", rel, ".env file not covered by .gitignore", count(filled),
                "1 'git add .' and it is public. Add .env* to .gitignore.")
        elif ign is None:
            rec("INFO", rel, ".env file present, no git setup found", count(filled),
                "Fine on your machine. Make sure it never reaches a repository or a zip you share.")

def scan_history(root):
    try:
        r = subprocess.run(["git", "-C", root, "log", "-p", "--all", "--no-color", "-U0", "--pretty=format:@@COMMIT %h"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    except Exception as e:
        rec("INFO", "git history", "not scanned", "", f"git not available: {e}")
        return
    commit, path, buf = "", "", []
    def flush():
        if buf and path:
            before = len(rows)
            scan_text("\n".join(buf), path, f"history {commit} ")
            for i in range(before, len(rows)):
                st, wh, fd, vl, wy = rows[i]
                rows[i] = (st, wh, fd + " (in git history)", vl, wy + " Removing the file today does not remove it from history.")
    for line in r.stdout.splitlines():
        if line.startswith("@@COMMIT "):
            flush(); buf = []; commit = line.split()[1]
        elif line.startswith("+++ b/"):
            flush(); buf = []; path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            buf.append(line[1:])
    flush()

def main():
    ap = argparse.ArgumentParser(description="Find likely exposed secrets in a project folder.")
    ap.add_argument("root")
    ap.add_argument("--history", action="store_true", help="also scan every past git commit")
    ap.add_argument("--include-deps", action="store_true", help="also scan node_modules, venv and vendor folders")
    ap.add_argument("--max-mb", type=float, default=5, help="skip files larger than this (default 5)")
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    if not os.path.isdir(root):
        sys.exit(f"Not a folder: {root}")

    files = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if a.include_deps or d not in SKIP_DIRS]
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            ext = os.path.splitext(f)[1].lower()
            if ext in BIN_EXT:
                continue
            try:
                if os.path.getsize(p) > a.max_mb * 1024 * 1024:
                    rec("INFO", rel, "skipped, larger than " + str(a.max_mb) + " MB")
                    continue
                with open(p, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if b"\x00" in raw[:4096]:
                continue
            text = raw.decode("utf-8", errors="replace")
            files += 1
            if f.endswith(".map") and is_served(rel):
                rec("WARN", rel, "Source map in a served folder", "",
                    "Lets anyone read your original source code, comments included.")
            if re.match(r"^\.env($|\.)", f) or f.endswith(".env"):
                envs[0] += 1
                check_env_file(root, rel, text)
            if f.lower() in ("id_rsa", "id_ed25519", "id_ecdsa") or ext in (".pem", ".key", ".p12", ".pfx"):
                rec("FAIL" if is_served(rel) else "WARN", rel, "Key file in the project", "",
                    "Private key files belong outside the project folder.")
            scan_text(text, rel)

    if a.history:
        if os.path.isdir(os.path.join(root, ".git")):
            current = {(r[2], r[3]) for r in rows}
            n = len(rows)
            scan_history(root)
            # keep only history hits that are no longer in today's files: those are the ones people miss
            rows[n:] = [r for r in rows[n:] if (r[2].replace(" (in git history)", ""), r[3]) not in current]
        else:
            rec("INFO", "git history", "not scanned", "", "No .git folder here.")

    order = {"FAIL": 0, "WARN": 1, "INFO": 2}
    reach = lambda wh: 0 if "served to visitors" in wh or "served folder" in wh else 1 if "front-end" in wh or "public variable" in wh else 2
    rows.sort(key=lambda r: (order[r[0]], reach(r[1] + r[2]), r[2], r[1]))
    if not rows:
        print("PASS  no likely secrets found")
    w = min(max((len(r[1]) for r in rows), default=10), 60)
    for st, wh, fd, vl, wy in rows:
        wh_s = wh if len(wh) <= w else "..." + wh[-(w - 3):]
        print(f"{st:4}  {wh_s:<{w}}  {fd}" + (f"  [{vl}]" if vl else "") + (f"  |  {wy}" if wy else ""))
    fails = sum(r[0] == "FAIL" for r in rows)
    warns = sum(r[0] == "WARN" for r in rows)
    infos = sum(r[0] == "INFO" for r in rows)
    print("-" * 60)
    labels = {p[1] for p in PATTERNS}
    groups = [
        (f"Known key formats ({len(PATTERNS)} kinds)", lambda f: f.split(" (in git")[0] in labels),
        ("Supabase and other signed tokens, decoded", lambda f: "JWT" in f or "Supabase" in f),
        ("Secret-looking values written into code", lambda f: f.startswith("Hard-coded")),
        ("Secret names in public env variables", lambda f: "public variable" in f),
        (f".env files ({envs[0]} found)", lambda f: ".env" in f),
        ("Key files and source maps", lambda f: f.startswith(("Key file", "Source map"))),
    ]
    print("Checks")
    for name, test in groups:
        hits = [r for r in rows if test(r[2])]
        worst = min((order[r[0]] for r in hits), default=9)
        st = {0: "FAIL", 1: "WARN", 2: "INFO"}.get(worst, "PASS")
        print(f"{st:4}  {name}: {len(hits)} finding" + ("" if len(hits) == 1 else "s"))
    if not a.history:
        print("INFO  Git history: not scanned. Add --history if the project uses git.")
    print("-" * 60)
    print(f"{files} text files scanned   FAIL={fails}  WARN={warns}  INFO={infos}")
    if fails:
        print("For every FAIL: rotate the key at the provider first, then remove it from the code.")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
