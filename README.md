# SecFest'26 CTF — Write-Ups

Write-ups from **SecFest'26 Capture the Flag**, hosted by Monzo on the Hack The Box CTF platform (28–30 October 2026).

Each note documents the full method, not just the solve path — the reasoning that led nowhere, the negative results worth proving, and the wrong submissions with the reason each one was made.

Nine of the event's 20 challenges, across four of its five categories. **Result: 25th of 139 teams · 7,650 points · 15 of 26 flags** — played solo as `Project_Hydra_Strike`.

---

## Index

### Challenges (solve order)

| # | Challenge | Category | Difficulty | Points | Flags | Focus | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 01 | [Stolen Variables](HTB-SecFest26-Stolen-Variables-Frontend-Embedded-IAM-Key-CloudTrail-Enumeration-DynamoDB-Scan.md) | Forensics | very easy | 825 | 7 / 7 | Frontend-embedded IAM key, CloudTrail enumeration, DynamoDB scan | Solved |
| 02 | [Leaked](HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery.md) | Forensics | hard | 925 | 1 / 1 | Linux memory, msfvenom reverse shell, page-cache recovery | Solved |
| 03 | [Re-Cars AI](HTB-SecFest26-Re-Cars-AI-Chatbot-Output-Filter-Bypass-Delimiter-Injection.md) | AI – ML | easy | 825 | 1 / 1 | LLM output-filter bypass via delimiter injection | Solved |
| 04 | [Cosmic Crisis](HTB-SecFest26-Cosmic-Crisis-LLM-Priority-Classifier-Baseline-Severity-Description.md) | AI – ML | easy | 875 | 1 / 1 | LLM priority classifier, solved by the baseline | Solved |
| 05 | [Stock Signals](HTB-SecFest26-Stock-Signals-AI-Bot-Fake-System-Update-Tier-Escalation.md) | AI – ML | easy | 875 | 1 / 1 | Free-to-premium tier escalation via a fake system update | Solved |
| 06 | [Neon Registry](HTB-SecFest26-Neon-Registry-MCP-Path-Traversal-pdfminer-CMap-Pickle-RCE.md) | AI – ML | hard | 975 | 1 / 1 | MCP path traversal, pdfminer CMap pickle RCE, SUID `/readflag` | Solved |
| 07 | [Logics & Business](HTB-SecFest26-Logics-and-Business-Non-Reciprocal-Exchange-Rate-Client-Only-Limits.md) | Secure Coding | medium | 950 | 1 / 1 | Non-reciprocal exchange rates, client-only limits, unvalidated amounts | Solved |
| 08 | [Based0x](HTB-SecFest26-Based0x-Layered-Hex-Base64-Encoding-Reversal.md) | Crypto | very easy | 800 | 1 / 1 | Layered hex/Base64 encoding reversal | Solved |
| 09 | [Me is Mey](HTB-SecFest26-Me-is-Mey-Non-Injective-Pre-Hash-Rotate-Collision.md) | Crypto | medium | 875 | 1 / 1 | Non-injective pre-hash rotate, SHA-256 second preimage | Solved |

### Event summary

| Note | Content |
| --- | --- |
| [SecFest'26 — Event MOC](00_MOC-HTB-SecFest26-Event.md) | Result by category, room index in solve order, the cross-room theme, seven transferable method rules, and open threads |

---

## Notes

- **Points** are the values recorded at solve time. HTB scores dynamically and the final per-challenge values were not captured; the recorded values sum to 7,925 against the final total of 7,650.
- **Flags.** Stolen Variables is graded as seven short-answer questions; Leaked's grader asks six questions before returning its flag; every other challenge has one flag. Flags and answers are published because the event has closed.
- The notes are published as written in an Obsidian vault. `[[wikilinks]]` and callouts render as plain text on GitHub; every link points to another note in this repo.
- MITRE ATT&CK mappings appear in the frontmatter where they apply; the AI – ML notes carry their framework mapping in the body instead. Several mappings are flagged as weak or unverified in the note; treat them as working hypotheses rather than citations.

## Use

Licensed CC BY 4.0 — reuse freely with attribution. Challenge names, prose, and artefacts remain the property of their owners.
