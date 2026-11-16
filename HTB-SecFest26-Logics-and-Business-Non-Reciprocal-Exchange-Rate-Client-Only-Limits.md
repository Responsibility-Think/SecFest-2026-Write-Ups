---
title: "HTB SecFest'26 — Logics & Business: Non-Reciprocal Exchange Rates, Client-Only Limits, Unvalidated Amounts"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
challenge: Logics & Business
app: "logics_and_business — Flask/SQLAlchemy banking API (two currencies, transfers, loans, promotions) behind a React/Vite frontend; handout ships exploit.py and an SMB-based note.md"
instance: "154.57.164.70:35761 (HTB Editor; respawn of 154.57.164.72:34646) — timer not recorded — flag 1 (Verify-gated)"
category: secure-coding
difficulty: medium
points: 950
type: writeup
status: complete
mitre:
  - T1594
  - T1587.004
  - T1190
  - T1565.001
  - T1657
tags:
  - writeup
  - HTB
  - Security
  - Secure_Coding
  - Web_App_Security
  - business-logic
  - input-validation
  - code-review
  - python
  - flask
  - kill-chain
related:
  - "[[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery]]"
aliases:
  - Logics & Business
  - SecFest26 Logics & Business
  - Logics and Business
created: 2026-10-29T05:50:12.835Z
updated: 2026-10-29T05:50:12.835Z
---

# Logics & Business — Non-Reciprocal Exchange Rates, Client-Only Limits, Unvalidated Amounts

> [!success] Solved — 2026-10-29 01:08 (platform timestamp)
> **Scenario Pwned.** Flag: `HTB{FR0NT_4ND_B4CK_TH3_BU51N355_3Y3_D035_533#!#$}`
> secure-coding · medium · 950 pts. Defend-and-verify: patch the Flask backend inside the hosted **HTB Editor**, Restart, Verify — the flag is returned by Verify, not found in the app.
> Live instance `154.57.164.70:35761` (respawn; first spawn `154.57.164.72:34646`), spawn timer not recorded. The only flag was gated behind Verify on the instance.
> Zero wrong flag submissions. **Four failed Verify runs before two passing ones** (§6). About an hour went to hunting an SMB share the handout described and the deployment did not have (§13).

> [!info] Scenario, verbatim
> SCENARIO NAME
> Logics & Business
> Secure Coding
> Please check the note.md file first for more information. In the fast-paced world of digital finance, even the smallest flaw can be exploited. A banking system designed for efficiency hides subtle cracks in its logic—loopholes that an astute mind can uncover. As transactions flow and numbers shift, will you identify the flaws buried within the system? Analyze the intricate interplay between frontend and backend operations, challenge assumptions, and restore order to the business logic before it's too late. The game is on—can you outthink the system?
>
> **Scenario hint, verbatim:** Modify transaction values to negative numbers or manipulate currency conversion rates in API requests to create a financial discrepancy.
>
> **Supplied artifact:** `secureCODING.zip` → `logics_and_business/` with `note.md`, `Dockerfile`, `build_docker.sh`, `config/{supervisord,nginx}.conf`, `challenge/flag.txt` (fake), `challenge/app/{app.py, blueprints/routes.py, utils/, frontend/, exploit.py, .env}`.

## 0. How the flag was obtained

1. Unpacked the handout. Read `note.md` (mount an SMB share, edit the code), the `Dockerfile` (ports 80/445/1337; `socat` → `/tmp/validate.py` on 1337; `/flag.txt` root-only, mode 400) and `exploit.py` (exchange round-trip profit test).
2. Read the backend and the frontend's money pages. **Root cause: the exchange rates are not reciprocal — 0.72 × 1.39 = 1.0008.** Eleven findings in total (§3).
3. Built a 17-check regression harness and reproduced every finding against the unpatched app locally: 8/17 pass, `exploit.py` profits (10,000 → 10,008 SCH).
4. Wrote patch v1 (reciprocal rate + round-down to the cent + server-side 40% cap + amount validation). Locally 17/17, exploit fails, 600,000 fuzzed round trips with zero profit.
5. Hunted for the SMB and checker ports: two full `-p-` scans across two shared hosts, an SMB handshake against every open port, a respawn, a Pwnbox detour. **No SMB anywhere** (§13).
6. Opened the web port in a browser: **HTB Editor** — file explorer plus Restart / Verify / View. Pasted v1 → Verify: *"Vulnerability check failed — the security issue has not been resolved."*
7. Proved v1 was saved and live, read the editor's API out of its JS bundle (§4), removed the cap → still failing.
8. **Added a temporary `after_request` logger to `routes.py` and ran Verify once.** The log exposed the checker's whole sequence: it demands that small round trips leave the balance **unchanged**. v1's round-down lost 0.013 SCH on the first one (§5).
9. Replaced the truncation with plain `amount * rate` over the exact reciprocal → Verify returned the flag. Stripped the logger and dead helpers, re-verified the clean file → flag again.

## 1. Shape of the challenge

Two things were not what the handout said.

| Handout said | Deployed reality |
|---|---|
| Mount an SMB share and edit files directly | **HTB Editor** web IDE on the single exposed port; files edited in the browser |
| Checker on port 1337 (`socat` → `/tmp/validate.py`) | **Verify button** → `GET /editor_api/verify` |
| `exploit.py` is the test | `exploit.py` is a sample; Verify runs a **hidden checker** with functional and security stages (§5) |

The structural fact: **the vulnerability is easy, the grading is not.** The arbitrage is visible in two lines of the rate table. The time went on (a) finding where a fix could be applied, and (b) learning that "fixed" means *no financial discrepancy in either direction* — a patch that safely destroys money fails exactly like the bug that creates it.

Category siblings for contrast: Withered Registry, Hollow Courier and Phantom Burn (CA2026) graded a pushed PR through a scored reviewer bot with hard and soft gates. This room has one binary Verify and no feedback beyond pass/fail — which is why the checker had to be instrumented (§5) rather than read.

## 2. The handout

**Container** (`Dockerfile`, `supervisord.conf`, `nginx.conf`): nginx :80 sends `/api/` to Flask :5000 and everything else to the Vite dev server :3000. Samba exports `[app]` → `/www/application`, guest-writable. `socat TCP-LISTEN:1337 … exec:'python3 -u /tmp/validate.py'` runs as root; `validate.py` is **not** shipped. `/flag.txt` is root-only and the backend runs as `www-data`, so the app can never read the flag — patching is the only path.

**Seeded users** (`app.py`): `xenon` and `rick` (administrator, 1e9 SCH / 5e8 BLF), `morty` (normal, 10,000 / 5,000). `rick` and `morty` are stored as pre-computed bcrypt hashes; the checker knows their plaintext (§5).

**`exploit.py`** registers a random user, exchanges **9,999** of its 10,000 SCH to Blemflark, exchanges the result back, and reports success if the returned Schmeckle figure exceeds 9,999. It parses both figures from the response message with `\d+\.\d+`, so the format `Exchanged {amount} {from} to {exchanged} {to}.` is load-bearing.

## 3. The vulnerabilities

### 3.1 Root cause — non-reciprocal exchange rates

```python
EXCHANGE_RATES = {
    'Schmeckle': {'Blemflark': 0.72, 'Schmeckle' : 1},
    'Blemflark': {'Schmeckle': 1.39, 'Blemflark' : 1}
}
```

1 / 0.72 = 1.38889, not 1.39. Every Schmeckle → Blemflark → Schmeckle round trip multiplies the balance by **1.0008**, unbounded with repetition:

| Start (SCH) | → BLF | → SCH back | Profit |
|---|---|---|---|
| 9,999 | 7,199.28 | 10,006.9992 | +7.9992 |
| 4,000 | 2,880 | 4,003.2 | +3.2 |
| 100 | 72 | 100.08 | +0.08 |

The frontend's `api.ts` hard-codes the same 0.72 / 1.39 with the comment *"Since the backend uses static exchange rates, we mimic the same logic here"* — the client bundle publishes the arbitrage.

### 3.2 The frontend–backend interplay

The scenario's own phrase. Every money rule the UI enforces is missing from the API:

| Rule | Frontend | Backend |
|---|---|---|
| Max exchange = 40% of source balance | `Exchange.tsx` | **absent** — `exploit.py`'s 9,999-of-10,000 depends on it |
| Exchange fees 0.5% / 0.25% | advertised on the page | **not implemented** |
| `amount > 0` on transfers and loans | `SendMoney.tsx`, `Loans.tsx` | **absent** |

### 3.3 Full findings

| # | Finding | Where | Verified locally |
|---|---|---|---|
| 1 | Non-reciprocal rates → round-trip profit | `EXCHANGE_RATES` | [Certain] exploit +8.0 SCH |
| 2 | 40% exchange cap enforced only client-side | `exchange_currency` | [Certain] |
| 3 | Advertised exchange fees not implemented | `exchange_currency` | [Certain] |
| 4 | **Negative `send_money` reverses the transfer** — `balance < -500` passes; sender `-= -500` gains, recipient `+= -500` loses | `send_money` | [Certain] attacker 10,500 / victim 9,500 |
| 5 | NaN or missing amount → 500. NaN does **not** corrupt balances: SQLite rejects the NaN `amount` row (NOT NULL) and the transaction rolls back | send / exchange / loans | [Certain] — corrected an earlier [Likely] prediction that balances would go NaN |
| 6 | Negative loans accepted; admin approval would *raise* `BANK_CAPITAL` | `request_loan` | [Certain] 201 |
| 7 | Promotion fee deducted with no balance check → negative balance | `promote` | [Certain] −500 SCH |
| 8 | `pending_closure` users keep a valid 1-day JWT and can still transact | all non-loan routes | [Certain] from code; not exercised |
| 9 | `float(None)` raises `TypeError`; handlers catch only `ValueError` → Werkzeug debugger page | send / exchange / loans | [Certain] locally |
| 10 | Hard-coded admin `xenon:wubbalubbadubdub`, committed `.env` JWT secret, `debug=True` | `app.py`, `.env` | [Certain] in handout; live values [Unverified] |
| 11 | `userService.getBalance` destructures an object as an array (display bug) | `api.ts` | [Certain] |

Findings 1, 4 and 6 are the ones the checker tests (§5). 8–11 were recorded and deliberately left out of the patch.

## 4. The deployed instance — HTB Editor

`curl http://154.57.164.70:35761/` returns `<title>HTB Editor</title>`, Prism.js for Python/JS/TS highlighting, and a built bundle at `/assets/index-*.js`. **That title is the tell.** In a browser: an Explorer pane listing `app.py`, `blueprints/`, `data/`, `exploit.py`, `instance/`, `utils/` (backend only, no `frontend/`) and Restart / Verify / View. View opens the bank at `/challenge/`; the bank's API answers at `/api/…` on the same port.

### 4.1 Editor API (read out of the bundle; axios `baseURL: "/editor_api"`)

| Call | Body / params | Returns |
|---|---|---|
| `GET /editor_api/directory` | — | nested `{name: {type, children}}` tree |
| `GET /editor_api/file` | `?path=blueprints/routes.py` | `{content}` |
| `POST /editor_api/save` | `{path, content, client_md5}` — MD5 of the content being replaced | `{md5, message: "File saved successfully"}` |
| `POST /editor_api/restart` | — | `{message: "Server restarted successfully!"}`; on failure `{error, details, logs}` |
| `GET /editor_api/verify` | — | `200 {"flag": …}` or `400 {"error": "Vulnerability check failed — …"}` |

Saves also travel over a Socket.IO channel (the green "Connected" badge). Driving the HTTP API directly made each iteration one scripted call: state-check → save → restart → verify.

### 4.2 Proving the patch was live before blaming the checker

The deployed `routes.py` matched the handout byte-for-byte apart from line endings (`diff -w` empty). After v1 was pasted, a fresh fetch of the file showed `parse_amount`, and a 9,999-SCH exchange against `/api/exchange` returned the 40% cap message. **Saved, running, and still failing** — so the checker was testing something the patch got *wrong*, not something it missed.

## 5. What Verify actually tests

Recovered by adding a temporary `@api_bp.after_request` hook that appended `method path BODY=… -> status RESP=…` to `data/verify_log.txt`, restarting, running Verify once, and reading the file back through `/editor_api/file`. Both diagnostic runs had the same shape:

**Stage 1 — functional reads, as `rick` (admin).** `POST /api/login` (`rick` / `!@#$$@Klopi#@#`), then `GET` profile, transactions, loans, `admin/stats`, `admin/loan_requests`, users, balance, `exchange/history`, `available_amount`.

**Stage 2 — functional writes.** Login `rick` again, login `morty` (`!@#$$@Klop!#@#`) → `POST /api/send_money` (random amount, schmeckle) → `POST /api/loans` (random amount, `term_months: 4`) → `GET /api/loans` → `POST /api/admin/approve_loan` → `POST /api/exchange` 10 SCH → BLF, which must yield 7.2 — **the forward rate has to stay 0.72**.

**Stage 3 — security.**
- Login `morty` → `POST /api/loans {"amount": -1000}` must be refused (got 400).
- `GET /api/balance`, then **~100 iterations** of: exchange a random amount in (0, 1) SCH → BLF, lift the BLF figure out of the response message, exchange exactly that back, `GET /api/balance` twice.

| Patch | First round trip | Morty SCH before → after | Verify |
|---|---|---|---|
| v1: round down to the cent | 0.623 → **0.44** → **0.61** | 12,590.961 → **12,590.948** | **fail** — checker stopped right after this trip |
| final: exact `amount * rate` | 0.436 → 0.31392 → 0.43599999999999994 | 13,480.948 → **13,480.948** | **pass** after all ~100 trips |

[Inference] Stage 3 asserts the Schmeckle balance is unchanged across each round trip — exactly, or within a tolerance below 0.01; the log cannot tell which. The unpatched app gains (0.623 → 0.44856 → 0.6234984), v1 loses, the exact reciprocal holds. `exploit.py`'s 9,999 case never appeared in either log.

> [!note] Why the checker parses the message
> The BLF figure sent back is the server's own float `repr()` (`0.10223999999999998`, `0.39096000000000003`), lifted from `Exchanged … to <x> Blemflark.` by regex. Changing the message format, or rounding only the *display*, would desynchronise the checker's view from the stored balances.

## 6. Every Verify run

| Run | `routes.py` variant | Live check | Verify |
|---|---|---|---|
| 1 (Kali browser) | v1: reciprocal + `Decimal` round-down + 40% cap + validation | cap message on 9,999 | **fail** |
| 2 (browser pane) | v1 unchanged — run to capture the raw response | — | **fail** — body is only `{"error": …}`, no `details`/`logs` |
| 3 | A: v1 minus the cap | 9,999 exchange → 200 | **fail** — rules the cap out |
| 4 | B: A + temporary request logger | — | **fail** — log shows the round-down loss (§5) |
| 5 | C: B with `convert()` → `amount * rate` | — | **pass** → flag |
| 6 | D: C minus the logger, `convert()`, `Decimal` import and dust check — the clean final | server MD5 `995062cfb6c22ac503640af7315e37cf` | **pass** → flag |

Every API save was gated: an FNV-1a hash of the server file was compared against the expected predecessor before writing and against the expected result after, so a mismatch would have skipped the write. Every variant ran locally (exploit + harness) before it touched the instance.

## 7. Timeline — 28–29 Oct 2026 (EDT)

| When | What |
|---|---|
| 28 Oct ~23:20 | Handout unpacked; findings enumerated; root cause identified |
| ~23:40 | Local baseline: exploit profits; harness 8/17 |
| 23:43–23:48 | Full `-p-` scan of `154.57.164.72` — 333 open, no Samba fingerprint |
| ~23:55 | v1 verified locally 17/17; ownership-gated SMB scripts tested against a two-share local Samba simulation |
| 29 Oct 00:04–00:08 | Rescan of `.72` (306 open); SMB handshake sweep → nothing |
| ~00:10 | Instance respawned → `154.57.164.70:35761` |
| 00:12–00:16 | Full scan of `.70` (279 open) → no SMB; 445 closed |
| 00:38 | Pwnbox: public IP, no internal route, 80/445/1337 filtered |
| ~00:50 | `<title>HTB Editor</title>` spotted; screenshot confirms the editor |
| ~00:55 | v1 pasted → Verify fails |
| 01:04:06 | Logger run — checker sequence captured; fails on the first round trip |
| 01:06:13 | Exact-reciprocal run — Verify returns the flag |
| ~01:07 | Clean final saved, restarted, Verify passes again |
| **01:08** | **Scenario Pwned** |

Times marked `~` are reconstructed from conversation order, not read off a clock. The two checker-run times are from the request log; 01:08 is the platform timestamp.

## 8. Final payload

The deliverable is the patch — one file, `blueprints/routes.py`, MD5 `995062cfb6c22ac503640af7315e37cf` as saved on the server.

```diff
--- a/blueprints/routes.py
+++ b/blueprints/routes.py
@@ -4,15 +4,29 @@
 from utils.models import User, Transaction, Loan
 from sqlalchemy.exc import IntegrityError
 from datetime import datetime, timedelta, timezone
+import math
 
 api_bp = Blueprint('api', __name__)
 
-# Static exchange rates (example rates)
+# Static exchange rates. The reverse rate MUST be the exact reciprocal of the
+# forward rate; 0.72 * 1.39 = 1.0008 let every round trip mint money.
+SCHMECKLE_TO_BLEMFLARK = 0.72
 EXCHANGE_RATES = {
-    'Schmeckle': {'Blemflark': 0.72, 'Schmeckle' : 1},
-    'Blemflark': {'Schmeckle': 1.39, 'Blemflark' : 1}
+    'Schmeckle': {'Blemflark': SCHMECKLE_TO_BLEMFLARK, 'Schmeckle' : 1},
+    'Blemflark': {'Schmeckle': 1 / SCHMECKLE_TO_BLEMFLARK, 'Blemflark' : 1}
 }
 
+
+def parse_amount(value):
+    """Return value as a positive, finite float, or None if it is not one."""
+    try:
+        amount = float(value)
+    except (TypeError, ValueError):
+        return None
+    if not math.isfinite(amount) or amount <= 0:
+        return None
+    return amount
+
 # Mock Bank Capital for Loans
 BANK_CAPITAL = 500_000_000_000  # 500 billion Schmeckle
 
@@ -134,11 +148,10 @@
     amount = data.get('amount')
     currency = data.get('currency')  # New field to specify currency
 
-    try:
-        amount = float(amount)
-    except ValueError:
+    amount = parse_amount(amount)
+    if amount is None:
         return jsonify({'success': False, 'message': 'Invalid amount.'}), 400
-    
+
     if not recipient_username or not amount or not currency:
         return jsonify({'success': False, 'message': 'Recipient, amount, and currency are required.'}), 400
         
@@ -190,17 +203,13 @@
     to_currency = data.get('to_currency')
     amount = data.get('amount')
 
-    try:
-        amount = float(amount)
-    except ValueError:
-        return jsonify({'success': False, 'message': 'Invalid amount.'}), 400    
-    
-    if not from_currency or not to_currency or not amount:
+    amount = parse_amount(amount)
+    if amount is None:
+        return jsonify({'success': False, 'message': 'Invalid amount.'}), 400
+
+    if not from_currency or not to_currency:
         return jsonify({'success': False, 'message': 'All fields are required.'}), 400
-    
-    if amount <= 0:
-        return jsonify({'success': False, 'message': 'Amount must be positive.'}), 400
-    
+
     user = User.query.get(user_id)
     if not user:
         return jsonify({'success': False, 'message': 'User not found.'}), 404
@@ -324,12 +333,8 @@
     amount = data.get('amount')
     term_months = data.get('term_months', 12)  # Default term
 
-    try:
-        amount = float(amount)
-    except ValueError:
-        return jsonify({'success': False, 'message': 'Invalid amount.'}), 400    
-    
-    if not amount:
+    amount = parse_amount(amount)
+    if amount is None:
         return jsonify({'success': False, 'message': 'Valid loan amount is required.'}), 400
     
     user = User.query.get(user_id)
@@ -395,7 +400,10 @@
     
     if user.role != 'normal':
         return jsonify({'success': False, 'message': 'Promotion is only available for normal users.'}), 400
-    
+
+    if user.schmeckle_balance < 1000:
+        return jsonify({'success': False, 'message': 'Insufficient Schmeckle balance for the 1000 Schmeckle promotion fee.'}), 400
+
     user.role = 'pending_promotion'
     user.schmeckle_balance -= 1000  # Deduct 1000 Schmeckle for promotion
```

`exchanged_amount = amount * rate` stays plain multiplication and the response message is untouched.

**Float behaviour of the exact reciprocal.** `1/0.72` is `1.3888888888888888`; `0.72 × (1/0.72)` is `0.9999999999999999`. Over 200,000 simulated round trips, including the checker's parse-the-message step, the balance came back **higher 0 · equal 195,083 · lower 4,917** (by float epsilon). A local replica of the checker's loop — 200 random sub-1 SCH trips — left the balance at exactly 10,000.0, and `exploit.py`'s 9,999 → 7,199.28 → **9,999.0**, not greater.

**Reproduction.** In the HTB Editor UI: open `blueprints/routes.py`, replace its content with the patched file, save, Restart, Verify. Scripted, from the editor page's own origin (state-checked):

```javascript
const P = 'blueprints/routes.py';
const cur = (await (await fetch('/editor_api/file?path=' + encodeURIComponent(P))).json()).content;
// compare cur against the expected original before writing; client_md5 = MD5 of cur
await fetch('/editor_api/save', {method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({path: P, content: PATCHED, client_md5: MD5_OF_CUR})});
await fetch('/editor_api/restart', {method: 'POST'});
await new Promise(r => setTimeout(r, 4000));
(await fetch('/editor_api/verify')).json();   // → {flag: "HTB{...}"}
```

## 9. Tools & techniques

`python3` · Flask / Flask-SQLAlchemy local repro · `curl` · `nmap` 7.99 (`-sS -p-`, `-sV`) · `smbclient` / `smbd` 4.19 (two-instance local simulation) · `vite` 5.4 local dev server · `xclip` · Claude built-in browser pane (`fetch` against the editor API from page context) · `sha256sum` / `md5sum` / FNV-1a

Concepts: reciprocal-rate arbitrage · client-side-only business rules · negative-amount transfer reversal · NaN/inf as bypasses for `<`/`<=` checks · SQLite NOT NULL rejecting NaN as an accidental safety net · `TypeError` vs `ValueError` on `float(None)` · float round-trip behaviour of an exact reciprocal · round-down as a *loss* discrepancy · reading an undocumented SPA's API from its minified bundle · **instrumenting the graded code with an `after_request` logger to observe a black-box checker** · hash-gated optimistic-concurrency writes (`client_md5`) · regression harness and fuzzing before every push

## 10. MITRE ATT&CK

- **T1594** Search Victim-Owned Websites — the public JS bundle hands over both rates and the client-only 40% cap
- **T1587.004** Develop Capabilities: Exploits — `exploit.py`: register, round-trip, profit check
- **T1190** Exploit Public-Facing Application — raw JSON to `/api/exchange`, `/api/send_money`, `/api/loans` with a self-registered account; the React checks never run
- **T1565.001** Data Manipulation: Stored Data Manipulation — balances inflated by round trips, a victim's balance reduced by a negative transfer
- **T1657** Financial Theft — currency minted from nothing and moved out of other users' accounts

> [!warning] Honest scope of this mapping
> **IDs assigned without access to the live ATT&CK matrix — unverified.** ATT&CK describes adversary behaviour against deployed systems and maps poorly onto *"the reverse rate was rounded"*. **T1657 is the weakest**: ATT&CK frames Financial Theft around extortion, BEC and cryptocurrency theft; minting an application's internal currency is adjacent, not central. T1594 is generous — reading a page's own JavaScript is the mildest form of it.
>
> **The accurate classification is source-level.** OWASP **A04:2021** Insecure Design (business-logic flaws) · **CWE-840** Business Logic Errors · **CWE-602** Client-Side Enforcement of Server-Side Security · **CWE-20** Improper Input Validation · **CWE-1339** Insufficient Precision or Accuracy of a Real Number. The CWE and OWASP IDs were assigned from knowledge and not checked against the live lists.

## 10a. Lockheed Martin Cyber Kill Chain

§10 names the techniques; the kill chain places them in order. **The chain applies here only in part.** Logics & Business is a defend-and-patch room, but `exploit.py` and the checker define a concrete attack path, so rows 1–4 and 7 describe that path as modelled by the handout. Rows 5 and 6 are empty because nothing is implanted — the attacker's own account and HTTP session are the whole operation.

| # | Phase | In Logics & Business | Basis | ATT&CK |
|---|---|---|---|---|
| 1 | Reconnaissance | Business rules shipped to the client: `api.ts` hard-codes 0.72 / 1.39 "to mimic" the backend; the 40% cap lives only in `Exchange.tsx`. The arbitrage is readable without sending a request | handout frontend source; the attacker reading it is [Inference] | T1594 |
| 2 | Weaponization | `exploit.py` (register → 9,999 S→B → B→S → profit check), plus the hint's negative-amount variants | `exploit.py` in the handout; hint text | T1587.004 |
| 3 | Delivery | Self-registered account, then direct JSON to the API — the browser and its validation are never involved | `exploit.py` uses `requests` directly | T1190 |
| 4 | Exploitation | Logic, not memory: the 1.0008 round-trip multiplier; `float()` accepting negatives; no server-side cap | §3, reproduced locally | T1190 |
| 5 | Installation | **None.** No code is planted. The registered account is the only foothold, and the abuse is repeatable through the public API at will | — | — |
| 6 | Command & Control | **None.** No implant; the attacker's own HTTP session is the only channel | — | — |
| 7 | Actions on Objectives | Financial fraud: +0.08% per round trip, unbounded with repetition; a −500 transfer moves 500 SCH out of a victim's account; negative loans would raise bank capital on approval | harness T1 / T7 / T10 against the unpatched app | T1565.001, T1657 |

> [!important] Where the chain breaks
> **Reconnaissance cannot be broken while business rules ship to the client.** A client-side copy of a rule is documentation for the attacker. Authority belongs on the server; the client copy can stay as UX only.
>
> **Exploitation is the only phase fully under the defender's control, and it is where the patch acts.** The exact reciprocal removes the profit; `parse_amount()` removes negative-value reversal and NaN/inf bypasses. Nothing upstream of it has to change.
>
> **Actions on Objectives is where detection lives**, because the fraud is invisible to every host signal — no process, no file, no connection out. The control is a **value-conservation invariant**: a user's holdings, valued at a fixed reference rate, must not grow across a self-exchange, and no transfer may increase its sender's balance. That is precisely what the Verify checker asserts ~100 times (§5). With Installation and C2 empty, eviction is closing the flaw and reversing ledger entries — there is no host to clean.

## 11. Detection / blue-team & fix notes

- **Derive inverse rates; never store both directions.** Store one rate and compute the other, or price everything against a single base currency. Two independently rounded constants will almost never multiply to exactly 1, and whichever side of 1 they land on is either a money printer or a money shredder.
- **Every client-side rule needs a server-side twin.** The 40% cap and `amount > 0` lived in React. The API is the trust boundary; the UI is advice.
- **Validate numbers as positive *and* finite, not "parses as float".** `float()` returns `nan`, `inf` and negatives without complaint. NaN defeats every ordering comparison (`balance < nan` is `False`), so a `<`-based balance check is not validation.
- **Rounding policy is a business decision, not a safety default.** Truncating every conversion is "safe" only against minting money — it destroys value per transaction, and this room's grader treats that as the same defect. For real money use integer minor units or `Decimal` end to end, with one documented rounding rule applied once. [Inference] Floats remain a latent defect even in the passing fix; it passes because 0.72 and its reciprocal behave well at the amounts tested.
- **Ledger reconciliation as detection.** Sum of all balances (at reference rates) plus bank capital should change only by external deposits and withdrawals. A drift that grows with exchange volume is the arbitrage signature.
- **Request-level signals.** Any negative or non-finite `amount` in an API body; high-frequency alternating S→B / B→S exchanges by one account; a transfer whose sender's balance rises.
- **Lifecycle states must gate every route.** `pending_closure` blocks login but not a live JWT — revoke tokens on state change, or check role on every money route.

## 12. Method notes

- **Open the web port in a browser before acting on the handout's deployment notes.** `note.md` described SMB and a checker port; the platform deployed an editor. `curl … | grep -i '<title>'` would have shown `HTB Editor` in one second and saved about an hour.
- **When a black-box grader rejects a fix you trust, instrument the code it grades.** One `after_request` hook writing to a file the editor can read turned *"Vulnerability check failed"* into a full request/response trace. It is your own instance and your own code; remove the hook after.
- **A failing exploit is not the definition of fixed.** `exploit.py` failed against v1 and Verify still rejected it. The grader's criterion — *no discrepancy in either direction* — was broader, and only the trace revealed it. The hint's phrase *"create a financial discrepancy"* was literal.
- **Over-engineering a fix can fail a grader that the minimal fix passes.** v1 had more defences than the final and was wrong: the extra rounding changed legitimate behaviour, and the checker tests legitimate behaviour.
- **Prove the patch is live before blaming the checker.** A fresh fetch of the file plus one behavioural request separated "not saved / not restarted" from "saved and wrong" in two calls.
- **Gate every scripted write with a before/after hash.** With a human editing the same file in another tab, that is the difference between iterating and clobbering.
- **On shared CTF hosts, an open port is not your port.** Both hosts carried hundreds of other players' instances. The SMB tooling refused to write without a canary-user ownership proof, and refused a simulated foreign share in testing.
- **No placeholder values in runnable commands.** Two rounds of commands were run with literal example ports (`12345`, `11111`, `22222`). Bake real values in, or have the script discover them and fail loudly.

## 13. Blind alleys — eliminated, do not re-walk

- **Full `-p-` scans of the instance hosts for SMB / 1337.** `.72`: 333 then 306 open; `.70`: 279. `nmap -sV` found no Samba; an `smbclient -L` handshake against every port found no `app` share; a generic "speaks SMB at all" sweep found nothing; 445 closed. **The editor deployment exposes one port only.**
- **Respawning for "the missing ports".** The respawn moved IP (`.72` → `.70`) and still showed one port. [Inference] The two addresses front the same docker pool — most open port numbers match between them.
- **Pwnbox as an internal route.** Public IP on `ens3`, no `tun0`; 80/445/1337 filtered on the instance host exactly as from Kali.
- **Diffing frontend source against handout checksums.** 0/23 matched — not because the build differed, but because `/src/*` returned the SPA's `index.html` fallback. The useful finding was the `<title>` it led to.
- **Netcat file transfer.** Needs command execution on both ends; the instance offers none, and the missing ports cannot be reached by any transport.
- **Removing the 40% cap.** Necessary to rule out, not the cause — Verify still failed without it (§6 run 3).
- **Werkzeug debugger / Vite file-read path.** Identified as an unintended route to code execution on the instance and deliberately not pursued: even with code execution, `/flag.txt` is root-only and only the checker reads it.

## 14. Open items

1. **`event`** taken from the SecFest'26 sibling notes, not read off the event page.
2. **`solves`** omitted — not read off the platform.
3. **Exact or tolerant balance comparison in stage 3** — not determinable from the log (§5). [Inference] tolerance below 0.01.
4. **Would the 40% cap pass alongside the exact rate?** Not tested. [Inference] yes — every checker exchange observed was far below 40% of the account's balance — but the checker's stages after the round-trip loop were never seen.
5. **`exploit.py`'s 9,999 case** never appeared in either checker log; whether the checker runs it at all is unknown.
6. **The working-folder copies of `routes.py`, `routes.py.diff`, `api.ts` and `logics_patch.tgz` (not included in this repository) are patch v1** — the version that **failed** Verify (it carries `MAX_EXCHANGE_RATIO` and the `Decimal` round-down). The passing patch is §8.
7. **Leftovers on the instance:** `data/verify_log.txt` and test users (`chk…`, `canary…`, `adamcanary77` on the first spawn). Harmless; reset on respawn.
8. **Live values of the hard-coded secrets** (`xenon` password, JWT secret) not checked against the instance.

## Cross-references
- [[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery]] — SecFest'26 sibling; source of the §10a kill-chain table format
- [[HTB-SecFest26-Based0x-Layered-Hex-Base64-Encoding-Reversal]] — SecFest'26 sibling; precedent for a kill-chain section on a non-intrusion room
- [[HTB-SecFest26-Stolen-Variables-Frontend-Embedded-IAM-Key-CloudTrail-Enumeration-DynamoDB-Scan]] — SecFest'26 sibling; another frontend that shipped what the backend should have kept

## Change Log
- 2026-10-29 — Note created. One flag, zero wrong submissions, four failed Verify runs documented with cause (§6). Handout-vs-deployment mismatch recorded (§1, §13). Checker sequence reconstructed from an instrumented run (§5). Final diff with server MD5 and float-behaviour evidence (§8). ATT&CK catalog with honest-scope callout naming OWASP A04:2021 and four CWEs (§10). **Lockheed Martin Cyber Kill Chain added on request (§10a)** — applies in part: rows 5–6 empty by nature, detection placed at Actions on Objectives via a value-conservation invariant. Open item 6 flags that the patch files already in this folder are the failed v1.
