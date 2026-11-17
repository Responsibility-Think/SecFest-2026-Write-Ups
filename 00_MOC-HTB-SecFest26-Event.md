---
type: moc
title: "HTB SecFest'26 — Event MOC: Result, Room Index and Cross-Room Method"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
category: event-summary
status: complete
mitre: []
tags:
  - writeup
  - HTB
  - Security
  - MOC
  - Methodology
related:
  - "[[HTB-SecFest26-Stolen-Variables-Frontend-Embedded-IAM-Key-CloudTrail-Enumeration-DynamoDB-Scan]]"
  - "[[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery]]"
  - "[[HTB-SecFest26-Re-Cars-AI-Chatbot-Output-Filter-Bypass-Delimiter-Injection]]"
  - "[[HTB-SecFest26-Cosmic-Crisis-LLM-Priority-Classifier-Baseline-Severity-Description]]"
  - "[[HTB-SecFest26-Stock-Signals-AI-Bot-Fake-System-Update-Tier-Escalation]]"
  - "[[HTB-SecFest26-Neon-Registry-MCP-Path-Traversal-pdfminer-CMap-Pickle-RCE]]"
  - "[[HTB-SecFest26-Logics-and-Business-Non-Reciprocal-Exchange-Rate-Client-Only-Limits]]"
  - "[[HTB-SecFest26-Based0x-Layered-Hex-Base64-Encoding-Reversal]]"
  - "[[HTB-SecFest26-Me-is-Mey-Non-Injective-Pre-Hash-Rotate-Collision]]"
aliases:
  - "SecFest'26 MOC"
  - "SecFest 2026 MOC"
  - "SecFest'26 Event Summary"
created: 2026-11-16T10:59:06.698Z
updated: 2026-11-16T10:59:06.698Z
---

# SecFest'26 — Event MOC

> [!info] Scope
> SecFest'26 Capture the Flag, hosted by Monzo on the Hack The Box CTF platform, ran 28–30 Oct 2026 as an individual event (one player per team). Played as `Project_Hydra_Strike`. All nine challenges solved are written up in this set, and every cross-room claim below is drawn from those nine notes. The result figures are read off the HTB certificate of participation and the platform's per-category solve panel, not recalled.

---

## 1. Result

| Measure | Value |
|---|---|
| Rank | **25th of 139 teams** (top 18%) |
| Points | **7,650** |
| Flags | **15 of 26** (58%) |
| Challenges solved | **9 of 20**, every one written up |
| Team | `Project_Hydra_Strike`, 1 player |
| Dates | 28–30 Oct 2026 |

The certificate counts 139 teams; the event page lists 138 joined.

### 1.1 By category

| Category | Flags | Solved | Not solved |
|---|---|---|---|
| Forensics | **8 / 8** | Stolen Variables (7), Leaked (1) | — |
| AI – ML | 4 / 6 | Re-Cars AI, Cosmic Crisis, Stock Signals, Neon Registry | 2 flags; challenge names not recorded |
| Crypto | 2 / 3 | Based0x, Me is Mey | The Gazorpazorps |
| Secure Coding | **1 / 1** | Logics & Business | — |
| Web | 0 / 8 | — | all 8; none has a note |

> [!note] How 15 flags map to 9 challenges
> [Inference] Stolen Variables is graded as seven short-answer questions, and each accepted answer counts as a flag. Leaked's raw-TCP grader asks six questions, then returns one `HTB{}` flag for the panel. Every other room has a single flag. 7 + 1 + 7 × 1 = 15, which matches both the certificate (which labels the figure "solved challenges") and the per-category panel (which calls them flags). The event page lists 20 challenges across 5 categories, and 19 single-flag challenges plus Stolen Variables' 7 gives exactly the 26 flags available, which supports the same reading. The platform does not state the rule.

> [!note] Points
> Each note records the challenge's value when it was solved. Those values sum to 7,925 against the certificate's 7,650. [Inference] HTB scores dynamically, so a challenge loses value as more teams solve it; the final per-challenge values were not captured.

---

## 2. Room index — solve order

Times are the platform timestamps recorded in each note's header. All nine solves fall within six hours, starting on day one.

| # | Solved | Challenge | Category | Difficulty · pts | Flags | Core weakness |
|---|---|---|---|---|---|---|
| 1 | 28 Oct 19:33 | [[HTB-SecFest26-Stolen-Variables-Frontend-Embedded-IAM-Key-CloudTrail-Enumeration-DynamoDB-Scan\|Stolen Variables]] | forensics | very easy · 825 | 7 | AWS IAM key exposed through the frontend; CloudTrail attributes the enumeration and the DynamoDB scan |
| 2 | 28 Oct 21:07 | [[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery\|Leaked]] | forensics | hard · 925 | 1 (grader 6/6) | Leaked SSH credentials and an msfvenom reverse shell; the payload hash recovered from the Linux page cache |
| 3 | 28 Oct 21:41 | [[HTB-SecFest26-Re-Cars-AI-Chatbot-Output-Filter-Bypass-Delimiter-Injection\|Re-Cars AI]] | AI/ML | easy · 825 | 1 | Post-generation output filter beaten by delimiter injection |
| 4 | 28 Oct 21:58 | [[HTB-SecFest26-Cosmic-Crisis-LLM-Priority-Classifier-Baseline-Severity-Description\|Cosmic Crisis]] | AI/ML | easy · 875 | 1 | LLM priority classifier; the baseline submission solved it |
| 5 | 28 Oct 22:14 | [[HTB-SecFest26-Stock-Signals-AI-Bot-Fake-System-Update-Tier-Escalation\|Stock Signals]] | AI/ML | easy · 875 | 1 | A fake system update rewrites the bot's free-tier check |
| 6 | 28 Oct 22:45 | [[HTB-SecFest26-Neon-Registry-MCP-Path-Traversal-pdfminer-CMap-Pickle-RCE\|Neon Registry]] | AI/ML | hard · 975 | 1 | MCP path traversal, pdfminer CMap pickle RCE, SUID `/readflag` |
| 7 | 29 Oct 01:08 | [[HTB-SecFest26-Logics-and-Business-Non-Reciprocal-Exchange-Rate-Client-Only-Limits\|Logics & Business]] | secure coding | medium · 950 | 1 | Non-reciprocal exchange rates and client-only limits; patched to pass Verify |
| 8 | 29 Oct 01:19 | [[HTB-SecFest26-Based0x-Layered-Hex-Base64-Encoding-Reversal\|Based0x]] | crypto | very easy · 800 | 1 | Hex and Base64 layers: encoding, not encryption |
| 9 | 29 Oct 01:32 | [[HTB-SecFest26-Me-is-Mey-Non-Injective-Pre-Hash-Rotate-Collision\|Me is Mey]] | crypto | medium · 875 | 1 | A non-injective byte rotate in front of SHA-256 gives a second preimage |

---

## 3. Event theme — the control sits in the wrong place

[Inference] Read across the nine notes, one shape repeats in every category: a defence exists, but it lives where the attacker can read it, rewrite it or step around it. This is a pattern drawn from the notes, not a theme published by the organisers.

- **In the client.** Logics & Business hard-codes its exchange rates in `api.ts` and enforces the 40% cap only in `Exchange.tsx`. Stolen Variables exposes a working IAM key through the frontend.
- **In the wrapper, not the primitive.** Me is Mey never touches SHA-256: the rotate in front of it uses shifts that sum to 7, not 8, so distinct inputs collide. Based0x's protection is encoding with no key at all.
- **In the model, not the code.** Re-Cars AI's guard is a separate post-generation filter, so changing the output's encoding beat it. Stock Signals' guard is the model's own judgment, so a fake system update beat it. Cosmic Crisis needed no bypass: the scenario's own instruction, followed literally, returned `High`.
- **In a trusted tool's input handling.** Neon Registry joins a caller-supplied absolute CMap name onto its directory with `os.path.join`, which discards the directory, and pdfminer's CMap loader unpickles the file it reaches.
- **Already gone.** Leaked starts from server credentials found on a public breach forum; the intrusion is a valid SSH login followed by a reverse shell.

---

## 4. Cross-room method — rules that transferred

### 4.1 Run the baseline before building the attack

Cosmic Crisis: the baseline was the solve, even though the slug and the framework mapping had already committed to prompt injection before a request was sent. Stock Signals: the baseline proved a real guard existed, which justified escalating. Opposite outcomes; the baseline is cheap either way.

### 4.2 Find where the control lives before choosing the bypass

Re-Cars AI's winning move, changing the output format, failed in Stock Signals because the defence there sat in model judgment rather than a post-filter. Re-Cars' own breakthrough was a `to`/`To` mismatch between the page and the chat, which proved the chat redaction was a second, separate filter.

### 4.3 Read the source before the data

Based0x's `source.py` was the complete decoder specification. In the Next.js rooms, Cosmic Crisis and Stock Signals, the page chunk mapped the whole client flow before any submission. Neon Registry's traversal read the server's own source, and the RCE fell out of `cmapdb.py`. Me is Mey's bug was found by summing the rotate's shift amounts.

### 4.4 Prove it before you submit it

- **Based0x:** re-encode the recovered plaintext and compare it byte-for-byte with `output.txt`.
- **Me is Mey:** run the handout's real `server.py` with a negative control, and check the live banner digest before sending.
- **Leaked:** sanity-check symbols with `pslist`, and look at a dump's bytes before trusting it. The zero-page dump would have failed Q6 silently.
- **Logics & Business:** prove the patch is live before blaming the checker.

### 4.5 The grader keys to the author's view of the artifact

Stolen Variables Q6: twelve CloudTrail calls share one second, and the accepted answer was the last row of the tied block, after three wrong submissions. Leaked Q4: the `pslist` creation second was rejected and the `linux.bash` second accepted. For second-precision "when" questions, carry both candidates.

### 4.6 Separate a stored secret from a hallucination

Re-Cars AI's `secret_flag: "active"` was invented by the model; it confirmed only that no such key exists. Stock Signals checked its leaked value with a second, differently worded request: an identical string, suffix included, means a stored value.

### 4.7 The minimal fix is the one that passes

Logics & Business v1 carried more defences than the final patch and failed Verify. Its extra rounding changed legitimate behaviour, and the checker tests legitimate behaviour as well as the exploit.

---

## 5. Open threads

1. **The Gazorpazorps** (crypto, medium, 900) — an AES-CBC session-cookie forgery: bit-flip the `buyer_info` cookie until it parses `certified=True`. Source enumerated, exploit not built; unsolved at close. No note in this set.
2. **Web, 0 of 8 flags.** No web challenge has a note, and whether any was attempted is not recorded.
3. **AI – ML, 2 of 6 flags not taken.** The unsolved challenges' names are not recorded.
4. **Final per-challenge points** were not captured (§1).

---

## Change Log

- 2026-11-16 — Created. Result from the HTB certificate of participation and the per-category solve panel; room data from the nine notes' frontmatter, headers and method notes; The Gazorpazorps as recorded during the event; host, format and challenge count from the HTB CTF event page.
