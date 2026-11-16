---
title: "HTB SecFest'26 — Stolen Variables: Frontend-Embedded IAM Key → CloudTrail Enumeration → DynamoDB Scan"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
challenge: Stolen Variables
app: NIIS visa-status portal — AWS Amplify static frontend (`d209nq8eaf2s88.amplifyapp.com`) with a long-lived IAM access key served in `/app/config.js`
category: forensics
difficulty: very easy
points: 825
type: writeup
status: complete
mitre:
  - T1552.001
  - T1078.004
  - T1580
  - T1526
  - T1213
tags:
  - writeup
  - HTB
  - Cloud
  - Security
  - DFIR
  - Incident_Response
  - Log_Analysis
  - aws
  - cloudtrail
  - cloudfront
  - dynamodb
  - credential-access
related: []
aliases:
  - Stolen Variables
  - SecFest26 Stolen Variables
created: 2026-10-28T23:41:22.062Z
updated: 2026-10-28T23:41:22.062Z
---

# Stolen Variables — Frontend-Embedded IAM Key → CloudTrail Enumeration → DynamoDB Scan

> [!success] Solved — 2026-10-28 19:33 local (platform timestamp)
> **Scenario Pwned 7/7.** No `HTB{}` string; the room grades seven short-answer questions off three CSV exports. 825 points · very easy · forensics.
> Three wrong submissions, all on Q6 (§6). Every other flag landed first attempt.

> [!info] Scenario, verbatim
> The National Immigration & Identity Service runs a public visa-status portal deployed on AWS Amplify. After detecting unusual API activity on one of its IAM users, the security team suspects that credentials embedded in a frontend JavaScript file were harvested and abused by a threat actor. Working as the analyst on Stolen Variables, you will use the provided artifacts to reconstruct the attacker's access timeline and identify what data was reached.

## 0. How the answers were obtained

1. Unzipped `SecFest_Stolen_Variables.zip` → `artifacts/` holding three CSVs: `cloudfront-access-logs.csv` (57 rows), `dynamodb.csv` (26 rows, CloudTrail data-event export), `event_history.csv` (576 rows, CloudTrail console management-event export). **No `config.js` is in the download** — Q3's "found in config.js" has to be answered from CloudTrail identity fields and the CloudFront fetch timeline, not from the file itself.
2. `cut -d, -f16 cloudfront-access-logs.csv | sort | uniq -c` → every request carries `x-host-header` `d209nq8eaf2s88.amplifyapp.com` or `staging.d209nq8eaf2s88.amplifyapp.com`. The Amplify app ID is the hostname label (Q1).
3. `grep -o 'arn=arn:aws:iam::[0-9]*:user/[^,]*' dynamodb.csv | sort | uniq -c` → two IAM users: `niis-developer-1` (18 events, 2026-03-06, STS session keys) and `niis-amplify-deployer` (8 events, 2026-03-07, long-lived key). The deployer is the exposed user (Q2); its `accesskeyid=AKIA453N4QOMFX23RUOL` is the only `AKIA` key in either CloudTrail export (Q3).
4. **Pivot:** `grep 115.166.125.51 cloudfront-access-logs.csv` → that IP browsed `staging.` at 15:32:01–:07 with a Chrome 145 UA and pulled `/app/config.js` four times (three `200`, one `304`). Four minutes later the same IP starts using the `AKIA` key. That timeline is what attributes the key to `config.js`.
5. `grep AKIA453N4QOMFX23RUOL event_history.csv | cut -d, -f3,7 | sort | head -1` → earliest use `2026-03-07T15:36:18Z` from `115.166.125.51`; all 484 uses of the key come from that one IP (Q4, Q5).
6. `grep 2026-03-07T15:36:18Z event_history.csv | cut -d, -f4,5,9` → **twelve** API calls share the first second. CloudTrail has no sub-second resolution. The accepted answer was the **last row of the tied block in the export** — `ListGraphqlApis` (Q6; see §6 for the three wrong attempts and why).
7. `grep -o 'tableName=[^,}]*' dynamodb.csv | sort | uniq -c` → one table, `niis-identity-records`; the deployer key's `Scan` against it at `15:53:52` is the final row of the data-event export (Q7).
8. Confirmed the attacker's successful calls (6 of 484) and the post-enumeration `aws-cli` session to settle "what data was reached" (§4).

## 1. Shape of the challenge

A pure log-reading room. Three CSVs, no live target, no binary, no decryption. Everything is one `grep`/`cut`/`sort | uniq -c` away except Q6, which is a tie-break with no evidence in the artifacts.

| File | Rows | What it is | Answers |
|---|---|---|---|
| `artifacts/cloudfront-access-logs.csv` | 57 | CloudFront standard access log, CSV-ified; `x-host-header` carries the Amplify hostname; `cs(User-Agent)` is URL-encoded with `%20` | Q1; the `config.js` fetch that links Q3 and Q4 |
| `artifacts/dynamodb.csv` | 26 | CloudTrail **data events** for `dynamodb.amazonaws.com`; `userIdentity` is a `{k=v, …}` blob in one cell; `eventTime` is `YYYY-MM-DD HH:MM:SS` with no zone | Q2, Q3, Q7 |
| `artifacts/event_history.csv` | 576 | CloudTrail **console "Download events" CSV** — `Event time` is `Z`-suffixed; `Resources` is a JSON array in one cell; rows are newest-first | Q4, Q5, Q6 |

The one structural fact that matters: `event_history.csv` is the console export, so its **row order is the console's order** — newest first, and arbitrary within a tied second. That is both the trap and the key for Q6.

## 2. The three populations in `event_history.csv`

| Population | Rows | Identity | Source | Nature |
|---|---|---|---|---|
| Attacker | 484 | `niis-amplify-deployer` / `AKIA453N4QOMFX23RUOL` | `115.166.125.51` | 15:36:18Z → 15:53:31Z, 2026-03-07 |
| Service-linked / AWS-internal | 51 + 34 | empty user or `resource-explorer-2`, `ASIA…` keys | `rds.amazonaws.com`, `resource-explorer-2.amazonaws.com` | `AssumeRole` + one read per service, hourly, both days — noise |
| Developer | 7 (mgmt) + 18 (data) | `niis-developer-1`, `ASIA…` session keys | `180.244.9.221` | 2026-03-06 14:33–14:34, legitimate table work — pre-incident baseline |

`grep -c AKIA event_history.csv` → 484. `cut -d, -f2 event_history.csv | sort | uniq -c` shows exactly one `AKIA` key; everything else is `ASIA` (temporary) or blank.

## 3. Harvest — CloudFront, 15:32

```
2026-03-07 15:32:01  GET /                302  staging.d209nq8eaf2s88.amplifyapp.com
2026-03-07 15:32:01  GET /index.html      200
2026-03-07 15:32:01  GET /app/config.js   200   ← first pull
2026-03-07 15:32:01  GET /app/script.js   200
2026-03-07 15:32:02  GET /app/config.js   200
2026-03-07 15:32:04  GET /app/config.js   200
2026-03-07 15:32:07  GET /app/config.js   304   ← browser revalidation
```

All from `115.166.125.51`, UA `Chrome/145.0.0.0` on Windows 10, against the **`staging.`** branch — the production hostname never served `config.js` to this IP. The other CloudFront visitors (`45.154.98.80`, `178.22.106.230`, `159.89.116.51`, `184.72.29.102`) are WordPress/`wlwmanifest.xml` scanner noise against the production host and are not the attacker.

[Inference] `config.js` held `AKIA453N4QOMFX23RUOL` and its secret. The file is not in the download; the attribution rests on the same IP using the key four minutes later with no other candidate source.

## 4. Abuse — CloudTrail, 15:36 → 15:53

**Phase 1 — automated sweep (15:36:18 → 15:37:17, UA `aws-sdk-go-v2/1.3.2`, 477 calls).** An alphabetical List/Describe/Get sweep across ~40 services in ~3-second batches: `acm · amplify · apigateway · appsync · sts` → `athena · autoscaling · backup · batch` → `cloud9 · clouddirectory · cloudformation` → `cloudhsm · cloudsearch · cloudtrail · codebuild · codecommit` → … → `ssm`. 394 `AccessDenied`, 72 `Client.UnauthorizedOperation` (EC2), 6 parameter errors. The tool is a Go enumerator with the SDK's default UA; it was not identified further.

**Six calls succeeded:**

```
15:36:18Z  sts       GetCallerIdentity
15:36:38Z  dynamodb  DescribeEndpoints
15:36:38Z  dynamodb  ListTables
15:37:10Z  s3        ListBuckets
15:37:17Z  sts       GetCallerIdentity
15:37:17Z  sts       GetSessionToken        → ASIA453N4QOMKBM67NC3 (never used)
```

**Phase 2 — hands-on-keyboard (15:50:31 → 15:53:52, UA `aws-cli/2.34.4 … os/linux#6.6.87.2-microsoft-standard-WSL2 … md/distrib#ubuntu.24`).** The operator switched to the CLI from an Ubuntu-on-WSL2 box: `GetCallerIdentity` → `ListBuckets` ×3 → `ListTables` ×2 → `Scan niis-identity-records` (`consistentRead=false`, no `limit`). The `Scan` is in `dynamodb.csv` only — data events are not in the management-event export.

**What was reached:** the full contents of `niis-identity-records` (unbounded `Scan`), the bucket list, and the account/caller identity. Nothing was written, no persistence was created, and the `GetSessionToken` credentials were never exercised.

## 5. The seven answers

| # | Question | Answer | Source · field | Command |
|---|---|---|---|---|
| 1 | Amplify application ID | `d209nq8eaf2s88` | `cloudfront-access-logs.csv` · `x-host-header` (col 16) | `cut -d, -f16 cloudfront-access-logs.csv \| sort \| uniq -c` |
| 2 | IAM user whose credentials were exposed | `niis-amplify-deployer` | `dynamodb.csv` · `userIdentity.arn` / `username`; `event_history.csv` · `User name` | `grep -o 'arn=arn:aws:iam::[0-9]*:user/[^,]*' dynamodb.csv \| sort \| uniq -c` |
| 3 | Access Key ID found in config.js | `AKIA453N4QOMFX23RUOL` | `dynamodb.csv` · `userIdentity.accesskeyid` (+ CloudFront `config.js` timeline, §3) | `grep -o 'accesskeyid=AKIA[A-Z0-9]*' dynamodb.csv \| sort -u` |
| 4 | Source IP of first use | `115.166.125.51` | `event_history.csv` · `Source IP address` (col 7) | `grep AKIA453N4QOMFX23RUOL event_history.csv \| cut -d, -f7 \| sort \| uniq -c` |
| 5 | Timestamp of first use | `2026-03-07T15:36:18Z` | `event_history.csv` · `Event time` (col 3) | `grep AKIA453N4QOMFX23RUOL event_history.csv \| cut -d, -f3 \| sort \| head -1` |
| 6 | First AWS API call | `ListGraphqlApis` | `event_history.csv` · `Event name` (col 5), **last row of the 15:36:18Z block** | `grep 2026-03-07T15:36:18Z event_history.csv \| cut -d, -f5 \| tail -1` |
| 7 | DynamoDB table accessed | `niis-identity-records` | `dynamodb.csv` · `requestParameters.tableName` | `grep -o 'tableName=[^,}]*' dynamodb.csv \| sort \| uniq -c` |

Q5 needed no timezone work: `event_history.csv` is already `Z`-suffixed and the question's `YYYY-MM-DDTHH:MM:SSZ` format matches the field verbatim.

## 6. Q6 — the tie-break, and three wrong submissions

Twelve calls carry `2026-03-07T15:36:18Z`. In export order:

```
GetRestApis · ListCertificates · GetClientCertificates · GetDomainNames · GetSdkTypes
GetUsagePlans · GetVpcLinks · GetApiKeys · GetCallerIdentity · ListApps · GetAccount · ListGraphqlApis
```

| Attempt | Submitted | Basis | Result |
|---|---|---|---|
| 1 | `GetCallerIdentity` | Only non-denied call in the second; `sts` is the one service out of alphabetical order in the batch, so the tool deliberately called it first | ✗ |
| 2 | `GetRestApis` | First row of the tied block in the file | ✗ |
| 3 | `GetCallerIdentity` | Resubmitted bare after ruling out a paste-formatting error | ✗ |
| 4 | `ListGraphqlApis` | **Last** row of the tied block in the file | ✓ |

**Why the file order is not evidence.** The export is newest-first by `Event time`, so a reader expects the oldest event at the bottom of a tie. Tested that against 25 `AssumeRole → first-use-of-minted-key` pairs that share a second (the `AssumeRole` must precede the use): 10 pairs listed the use *above* the `AssumeRole`, 15 listed it *below*. Within a second, the console export's order is arbitrary. The author's answer is therefore the row the **console displays at the bottom** of the tie — not the call that was executed first, which the artifacts cannot show.

> [!important] Transferable rule
> When a question asks for "first" and the artifact's timestamp resolution produces a tie, the grader's answer is whatever sits at the chronological end of the **author's view of the artifact** — for a CloudTrail console export, the last row of the tied block. Try that before any behavioural argument (whoami-first, non-denied-first, alphabetical-first). The behavioural argument was sound and cost two attempts.

[Inference] The mechanism — "author read the bottom row" — is the simplest explanation consistent with the accepted answer; it is not confirmed by the platform.

## 7. Final payload

```bash
cd artifacts/

# Q1 — Amplify app ID from the CloudFront host header
cut -d, -f16 cloudfront-access-logs.csv | sort | uniq -c
#   42 d209nq8eaf2s88.amplifyapp.com   15 staging.d209nq8eaf2s88.amplifyapp.com

# Q2 / Q3 — IAM user and long-lived key from the DynamoDB data-event identity blob
grep -o 'arn=arn:aws:iam::[0-9]*:user/[^,]*' dynamodb.csv | sort | uniq -c
grep -o 'accesskeyid=AKIA[A-Z0-9]*'          dynamodb.csv | sort -u

# config.js harvest that links the key to the frontend
grep 115.166.125.51 cloudfront-access-logs.csv | cut -d, -f1,2,6,8,9,16 | sort

# Q4 / Q5 — first use of the key
grep AKIA453N4QOMFX23RUOL event_history.csv | cut -d, -f3,7 | sort | head -1
#   2026-03-07T15:36:18Z,115.166.125.51

# Q6 — the tied first second, export order; accepted answer is the last row
grep 2026-03-07T15:36:18Z event_history.csv | cut -d, -f4,5,9
grep 2026-03-07T15:36:18Z event_history.csv | cut -d, -f5 | tail -1
#   ListGraphqlApis

# Q7 — table accessed
grep -o 'tableName=[^,}]*' dynamodb.csv | sort | uniq -c

# Outcome split for the stolen key (6 OK / 394 AccessDenied / 72 UnauthorizedOperation)
grep AKIA453N4QOMFX23RUOL event_history.csv | awk -F, '$9==""{print $3","$4","$5}' | sort
```

`cut -d,` is safe on every column used above; the only comma-bearing cells (`User agent`, `Resources`) sit to the right of them. For anything touching those, use Python's `csv` module — that is how the tie-order test in §6 and the population counts in §2 were run.

## 8. Tools & techniques
`unzip` · `grep` / `cut` / `awk` / `sort` / `uniq` · Python 3 `csv` module (run with `-I` against untrusted input) · CloudTrail console CSV export · CloudFront standard log fields
Concepts: cloud credential harvest from static frontends · long-lived (`AKIA`) vs temporary (`ASIA`) key triage · CloudTrail management vs data event exports · automated-enumeration fingerprinting (alphabetical service batches, bare SDK UA) · tool-switch as a phase boundary (SDK sweep → CLI hands-on) · timestamp-tie resolution against the author's view of the artifact

## 9. MITRE ATT&CK
- **T1552.001** Unsecured Credentials: Credentials In Files — an IAM access key served from `/app/config.js` on a public Amplify branch
- **T1078.004** Valid Accounts: Cloud Accounts — the `niis-amplify-deployer` key replayed from `115.166.125.51`
- **T1580** Cloud Infrastructure Discovery — the 477-call `aws-sdk-go-v2` List/Describe sweep across ~40 services
- **T1526** Cloud Service Discovery — `GetCallerIdentity`, `ListTables`, `ListBuckets` confirming the key's reach
- **T1213** Data from Information Repositories — unbounded `Scan` of `niis-identity-records`

> [!note] Honest scope of this mapping
> IDs assigned without access to the live matrix. **T1213** is the weakest: ATT&CK has no DynamoDB-specific technique, and T1530 (Data from Cloud Storage) is written for object stores, so a reviewer could argue either. T1580 and T1526 overlap on the sweep; both are kept because the sweep hit infrastructure services (EC2, autoscaling) and application services (amplify, appsync) alike. No initial-access, persistence, or exfiltration techniques are claimed — the `Scan` response is not in the evidence, and the `GetSessionToken` credentials were never used. The underlying defect is OWASP **A02:2021** Cryptographic Failures / **A05:2021** Security Misconfiguration — a secret committed to a frontend bundle.

## 10. Detection / blue-team & fix notes
- **Highest-value alert:** a long-lived `AKIA` key that has only ever been used by a CI/CD pipeline suddenly emitting `GetCallerIdentity` followed by >100 `AccessDenied` events across unrelated services inside a minute. The sweep here produced 394 denials in 59 seconds; one GuardDuty `Recon:IAMUser/*` or a CloudWatch metric filter on `errorCode = AccessDenied` grouped by `accessKeyId` catches it in the first batch.
- **Second:** a deployer key used from a residential/VPS IP (`115.166.125.51`) rather than the Amplify build service. `aws:SourceIp` / `aws:ViaAWSService` conditions on the deployer policy would have denied all 484 calls.
- **Third:** `userAgent` switching from `aws-sdk-go-v2/1.3.2` to `aws-cli/2.34.4 … WSL2` on the same key within 15 minutes — the SDK-sweep-then-CLI pattern is an operator, not a pipeline.
- **DynamoDB `Scan` with no `limit` from a principal that has never read the table** — data-event logging on sensitive tables is what made Q7 answerable; without it the exfil is invisible.
- **The actual fix:** no static credentials in a frontend bundle, ever. Amplify-hosted apps reach backend resources through Cognito identity pools / IAM roles, and a build-time `.env` must never be copied into `public/`. Rotate `AKIA453N4QOMFX23RUOL`, audit `staging.` for other secrets, and scope the deployer to `amplify:*` on its own app only — the sweep shows it also held `dynamodb:ListTables`, `dynamodb:Scan`, and `s3:ListBuckets`.
- **CloudFront:** `/app/config.js` fetched four times in six seconds by one client with a `304` at the end is a human reading a file, not a page load. Low-signal alone; worth correlating when the same IP hits the API.

## 11. Method notes
- **Check the download for the named file before planning around it.** The question says "found in config.js"; the ZIP has no `config.js`. Ten seconds of `unzip -l` reframed Q3 as a CloudTrail question with a CloudFront corroboration.
- **Verify the ordering assumption before using file order as evidence.** The 25-pair `AssumeRole` test took one script and would have saved one wrong submission if run before attempt 2 rather than after. The result — order within a tied second is arbitrary — is now a known property of CloudTrail console exports.
- **Behavioural reasoning is for the writeup, not the flag field.** `GetCallerIdentity` *was* almost certainly the real first call (the only out-of-alphabetical service, the only success, the textbook whoami). The grader does not know that either; it knows what its author read off the screen. Spend attempts on the author's view first.
- **`cut -d,` works until it doesn't.** It was correct for every column used here, and the stray `P`/`Z`/`n` values in a `uniq -c` over the error-code column were the warning that a comma-bearing UA field sits to the right. Switch to `csv` the moment a count looks wrong.
- **Separate baseline before attributing.** `niis-developer-1` scanned the same table a day earlier from a different IP with session keys. Had Q7 been "who accessed the table," that row is the decoy.

## 12. Open items
- The enumeration tool behind `aws-sdk-go-v2/1.3.2` was not identified. The alphabetical, ~4-service, ~3-second batch pattern with `sts` pulled to the front is a fingerprint worth matching against known Go AWS enumerators if the room is revisited.
- Whether the grader keys Q6 to "last row of the tied block" as a rule, or `ListGraphqlApis` was chosen another way, is unconfirmed — one accepted answer, no per-question feedback beyond correct/incorrect.
- `GetSessionToken` minted `ASIA453N4QOMKBM67NC3` at 15:37:17Z; no later event uses it in either export. Not established whether it was used outside the export window.
- The `Scan` response size is not in the evidence; "full table read" is inferred from the absence of a `limit` parameter, not from `responseElements`.

## Cross-references
- No cross-references within this event.

## Change Log
- 2026-10-28 — Note created. Full solve documented: three-artifact inventory, population split, CloudFront harvest timeline, two-phase abuse chain with the six successful calls, all seven answers with source field and reproduction command, the Q6 tie-break with the three wrong submissions and the 25-pair ordering test that falsified file-order-as-evidence, ATT&CK mapping with honest-scope callout, detections, method notes, and open items.
