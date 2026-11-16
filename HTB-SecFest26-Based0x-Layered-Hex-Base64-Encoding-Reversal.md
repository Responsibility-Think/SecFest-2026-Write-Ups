---
title: "HTB SecFest'26 — Based0x: Layered Hex/Base64 Encoding Reversal"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
challenge: Based0x
app: "`source.py` + `output.txt` — static crypto handout; the flag paragraph is hex-encoded, base64-encoded three times, then hex-encoded again. No key, no instance"
category: crypto
difficulty: very easy
points: 800
solves: 28
type: writeup
status: complete
mitre:
  - T1027.013
  - T1132.001
  - T1140
tags:
  - writeup
  - HTB
  - Security
  - Cryptography
  - crypto-encoding
  - obfuscation
  - kill-chain
related:
  - "[[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery]]"
aliases:
  - Based0x
  - SecFest26 Based0x
created: 2026-10-29T06:04:19.133Z
updated: 2026-10-29T06:04:19.133Z
---

# Based0x — Layered Hex/Base64 Encoding Reversal

> [!success] Solved — 2026-10-29 01:19 (platform timestamp)
> **Scenario Pwned.** Flag: `HTB{enc0d1ng_1s_n0t_th3_s4m3_4s_encrypt10n}`
> crypto · very easy · 800 pts. Static handout, no instance. Decoded offline and proven complete by a byte-identical round trip before submission (§5).

> [!info] Scenario, verbatim
> Before starting the journey into the world of cryptography, one should first build strong fundamental knowledge of how encoding schemes work. Lesson #1: Encoding is different than encryption.

## 0. How the flag was obtained

1. Unzipped the handout → `crypto_based0x/` holding `source.py` (285 B) and `output.txt` (5,784 B). No instance, no remote service, no `secret.py`.
2. Read `source.py`: `FLAG` → `.hex()` → `base64.b64encode` ×3 → `.hex()` → `output.txt`. Every step is a public, keyless, invertible transform.
3. **Inverted the pipeline in reverse order:** unhex → base64-decode ×3 → unhex.
4. The result is a 608-byte paragraph of filler text. The flag is its tail, at byte offset 565, after `Here is your flag : `.
5. Re-ran `source.py`'s own `encode()` on the recovered paragraph → output byte-identical to `output.txt`. Decode complete, no layer skipped.
6. Submitted `HTB{enc0d1ng_1s_n0t_th3_s4m3_4s_encrypt10n}` → Scenario Pwned, 01:19.

## 1. Shape of the challenge

A two-file handout. There is no key, no randomness, and no search space anywhere in the pipeline — **the source file is the decoder specification.** The only work is applying the inverse operations in the right order and confirming nothing was missed.

| File | Size | SHA-256 | What it is |
|---|---|---|---|
| `ab3bca75-a21bac8b-696d-46ec-a79f-e94b8ef343d0.zip` | 2,440 B | `77e87436df5c42cd3418c003ceef0bb6078b67558a9c40345530cf36e8d956ca` | The download. Both members dated 2023-04-24 11:10 |
| `crypto_based0x/source.py` | 285 B | `6fa43b9913c45b08d8b5b25c0d78ee3d7672408ebd2b630e11318dd64f4cba9c` | The encoder. Imports `FLAG` from a `secret` module that is not shipped |
| `crypto_based0x/output.txt` | 5,784 B | `aa5f01dde0f05542c56ff924f63ae0131845f643c9c94327c66d7908f0c2e92b` | One line of lowercase hex, no trailing newline |

`source.py`, verbatim:

```python
from secret import FLAG
import base64


def encode(m):
    m = m.hex().encode()
    for _ in range(3):
        m = base64.b64encode(m)
    return m


if __name__ == "__main__":
    encoded_flag = encode(FLAG)

    with open('output.txt', 'w') as f:
        f.write(encoded_flag.hex())
```

`FLAG` is the whole 608-byte paragraph, not just the `HTB{}` string. The filler text in front of the flag pads the input, so every layer is large enough that the flag cannot be read off any intermediate layer.

## 2. The pipeline, forward and back

Five transforms. Hex is applied first and last, so the inverse starts and ends with unhex.

| Encode step | Produces | Bytes | Shannon H (bits/byte) | Inverse |
|---|---|---|---|---|
| `FLAG` (plaintext) | English paragraph | 608 | 4.52 | — |
| `.hex()` | hex digits | 1,216 | 3.32 | `bytes.fromhex` |
| `b64encode` #1 | base64 text | 1,624 | 4.39 | `b64decode` |
| `b64encode` #2 | base64 text | 2,168 | 5.07 | `b64decode` |
| `b64encode` #3 | base64 text | 2,892 | 5.23 | `b64decode` |
| `.hex()` → `output.txt` | hex digits | 5,784 | 3.29 | `bytes.fromhex` |

**The size ladder counts the layers.** Hex doubles the length. Base64 multiplies it by 4/3, rounded up to a multiple of 4: 1,216 → 1,624 → 2,168 → 2,892. The total expansion is 9.5×. Given only `output.txt`, working this arithmetic backwards from 5,784 tells you how many layers to expect before any decoding.

**The entropy column separates encoding from encryption.** Every layer stays at or below its alphabet's ceiling: 4 bits per character for hex, 6 for base64. For comparison, 608 random bytes measured 7.67 bits/byte in the same script. Ciphertext sits near 8. Nothing in this pipeline gets close.

## 3. Recognising each layer without the source

The source made this trivial, but the same blob found in a log or a payload has no `source.py` next to it. Each layer has a tell:

| Layer | Tell | Measured here |
|---|---|---|
| Hex | Charset exactly `[0-9a-f]`, even length | `output.txt`: 16 distinct byte values, even length |
| Base64 | Charset `[A-Za-z0-9+/=]`, length a multiple of 4, `=` padding only at the end | All three base64 layers. The padding was `=`, `==`, `==` from the outermost inwards |
| **Base64 of hex** | **Every 4-character group starts with `M`, `N`, `O`, `Y` or `Z`** | Innermost base64 layer: group-lead set = `MNOYZ` exactly |
| Base64 of base64 | Group leads spread across `K–O`, `Q–W`, `Y–e`, plus `P` where the inner layer has `=` padding | Outer two layers: `MNOPQRSTUVWYZabcde` and `MNPQRSTUVWYZabde` |

Why the base64-of-hex tell holds: the first character of each base64 group encodes the top 6 bits of that group's first byte. Hex digits are bytes `0x30–0x39` and `0x61–0x66`, so their top 6 bits are only ever 12–14 (`M`–`O`) or 24–25 (`Y`–`Z`). A base64 blob whose groups all start with those five letters is base64 of hex, before you decode it. The `P` in the outer layers comes the same way from `=` (`0x3D`, top 6 bits = 15) in the layer beneath.

**The general rule: if a decode returns another printable blob, keep peeling.** Stop when the output is natural language, a file magic number, or high-entropy bytes (that last one is where encryption starts and encoding ends). `grep HTB{` on any intermediate layer returns nothing. Only the final layer contains the flag.

## 4. Why this is encoding, not encryption

The flag is the whole lesson: `enc0d1ng_1s_n0t_th3_s4m3_4s_encrypt10n`.

- **Encoding** changes the representation of data using a public, keyless algorithm. Its purpose is transport and compatibility, such as binary-safe text or URL-safe strings. Anyone who knows or guesses the scheme can reverse it.
- **Encryption** requires a key. Its security rests on the secrecy of the key, not the algorithm (Kerckhoffs's principle).
- **Stacking encodings adds no work factor.** Five layers cost five decode calls. There is no key space to search, so the attacker's effort grows linearly with the layer count and never exponentially.

Real-world versions of the same mistake: HTTP Basic authentication sends `user:password` in base64; Kubernetes Secrets are base64-encoded, not encrypted, unless encryption at rest is configured; and `powershell -EncodedCommand` is base64 of UTF-16LE text, which obscures a command from casual reading but protects nothing.

## 5. Final payload

Shell (`xxd` + coreutils):

```bash
unzip ab3bca75-a21bac8b-696d-46ec-a79f-e94b8ef343d0.zip
cd crypto_based0x/

xxd -r -p output.txt | base64 -d | base64 -d | base64 -d | xxd -r -p | grep -o 'HTB{[^}]*}'
#   HTB{enc0d1ng_1s_n0t_th3_s4m3_4s_encrypt10n}
```

Python (standard library only), with the round-trip proof. Saved as `decode.py` and run as `python3 -I decode.py output.txt` from inside `crypto_based0x/`:

```python
import base64, sys

s = open(sys.argv[1]).read().strip()
m = bytes.fromhex(s)                          # undo the final .hex()
for _ in range(3):
    m = base64.b64decode(m, validate=True)    # undo b64encode x3
pt = bytes.fromhex(m.decode())                # undo the first .hex()
print(pt[pt.find(b"HTB{"):].decode())

def encode(x):                                # source.py's encode(), same logic
    x = x.hex().encode()
    for _ in range(3):
        x = base64.b64encode(x)
    return x

assert encode(pt).hex() == s                  # byte-identical round trip
print("round trip OK")
```

`validate=True` makes `b64decode` raise on any non-alphabet character instead of silently discarding it, so a mis-ordered layer fails loudly.

CyberChef equivalent: **From Hex → From Base64 → From Base64 → From Base64 → From Hex**. Not used for the solve.

## 6. Tools & techniques
`unzip` 6.00 · `xxd` (2023-10-25, `-r -p`) · GNU coreutils `base64` 9.4 (`-d`) · Python 3.13 `base64` / `bytes.fromhex` (run with `-I` against untrusted input) · `sha256sum` · CyberChef (equivalent recipe, not used)
Concepts: encoding vs encryption · identifying multi-layer encoding by charset, length and base64 group-lead characters · size-ladder arithmetic (×2 per hex, ×4/3 per base64) as a layer counter · Shannon entropy against the alphabet ceiling as the encoded-vs-encrypted discriminator · round-trip re-encoding as proof that a decode is complete

## 7. MITRE ATT&CK
- **T1027.013** Obfuscated Files or Information: Encrypted/Encoded File — the technique class the room teaches: content hidden behind stacked standard encodings
- **T1132.001** Data Encoding: Standard Encoding — hex and base64 are the standard encodings this technique covers when they wrap C2 traffic
- **T1140** Deobfuscate/Decode Files or Information — the adversary-side counterpart of the solve: reversing the same layers at runtime on a target

> [!note] Honest scope of this mapping
> **No intrusion took place.** Based0x has no actor, no target and no timeline, so none of these techniques was *performed* in the artifacts. The IDs catalog the technique class for queryability. Technique names were checked against attack.mitre.org search results on 2026-10-29; the full technique pages were not read. **T1132.001 is the weakest**: it is specific to command-and-control traffic, and this room has no network channel at all. The accurate classification of the underlying mistake, treating encoding as protection, is OWASP **A02:2021** Cryptographic Failures and CWE-311 Missing Encryption of Sensitive Data. CWE-261 Weak Encoding for Password is the credential-specific sibling. The CWE IDs were assigned from knowledge and not checked against the live CWE list.

## 7a. Lockheed Martin Cyber Kill Chain

§7 names the technique class; the kill chain says where defenders meet it. **Based0x is not an intrusion, so the "In Based0x" column is empty by design.** No phase happened. The other columns map where stacked hex/base64 of exactly this shape turns up in real intrusions, so the room's lesson can be placed on a phase. [Inference] Those columns are drawn from general tradecraft, not from evidence in this room.

| # | Phase | In Based0x | Where layered standard encoding appears in real intrusions | ATT&CK |
|---|---|---|---|---|
| 1 | Reconnaissance | — | No meaningful role | — |
| 2 | Weaponization | — | Payload or script wrapped in nested base64/hex so static signatures and plain `strings` miss it. Same shape as `output.txt` | T1027.013 |
| 3 | Delivery | — | Encoded blob carried in a macro, HTA, LNK argument or attachment, e.g. `powershell -EncodedCommand <base64>` | T1027.013 |
| 4 | Exploitation | — | Stager decodes in memory at execution, running the same inversion as §5 | T1140 |
| 5 | Installation | — | Persistence entry (Run value, scheduled-task argument, cron line) stores the encoded command rather than a readable one. The persistence mechanism itself is out of scope here | T1027.013 |
| 6 | Command & Control | — | Tasking and results wrapped in base64/hex inside HTTP bodies, cookies or DNS labels | T1132.001 |
| 7 | Actions on Objectives | — | Staged or exfiltrated data encoded so it survives text-only channels. Exfiltration itself would be T1041 over the C2 channel | T1132.001 |

> [!important] Where the chain breaks
> Encoding defends nothing at any phase. Every layer in this room cost one decode call, and an attacker's layers cost a defender the same. **The defender's lever is the inverse of the attacker's: decode before you inspect.** [Likely] Sensors that decode recursively collapse rows 2–5 the same way §5 did. Examples: mail gateways that unpack nested encodings, AMSI scanning PowerShell content after the engine deobfuscates it, and Script Block Logging (Event ID 4104) recording the decoded script block. Row 6 is the exception that matters: once real encryption replaces encoding on the C2 channel (compare the AdaptixC2 RC4 beacon traffic in Holmes CTF 2026's Borrowed Name), decoding no longer works and the defender needs the key.

## 8. Detection / blue-team & fix notes
- **The fix:** if the goal is confidentiality, use authenticated encryption with a managed key (for example AES-GCM or libsodium `secretbox`). Never use encoding for this. Adding encoding layers never adds protection (§4).
- **Fingerprint nested base64 before decoding it.** Length a multiple of 4, restricted charset, and for base64-of-hex, group-lead characters limited to `M N O Y Z` (§3). A detector that decodes, re-tests for a printable base64 or hex result, and repeats will peel this blob to plaintext in five iterations.
- **Entropy separates encoded from encrypted.** Hex tops out at 4 bits/char and base64 at 6. Ciphertext approaches 8 bits/byte. A blob measuring 3.3–5.2 like every layer here (§2) is a decode candidate, not a crypto problem.
- [Likely] **Watch the decode, not the blob.** Process-creation logs (Sysmon EID 1, Security 4688) show `-EncodedCommand` / `-enc`, `FromBase64String`, `base64 -d | sh`, and `xxd -r -p` even when the blob itself is unreadable.
- [Likely] **Secret scanning must decode.** A scanner that only regex-matches raw strings misses a credential committed as base64 or hex. The Kubernetes Secret manifest is the common case.

## 9. Method notes
- **Read the source before the data.** `source.py` is the complete decoder specification. Nothing in `output.txt` needed guessing, analysis or tooling beyond the standard library.
- **Reverse the order as well as the operations.** Hex was applied both first and last. Applying the inverses in forward order fails at the first `b64decode`.
- **Prove the decode with a round trip.** Re-encoding the recovered plaintext and comparing against `output.txt` is one line and proves no layer was skipped or mis-decoded. That is cheaper and stronger than reasoning about it.
- **Use `validate=True` on `b64decode`.** The default silently drops non-alphabet bytes, which can turn a wrong layer order into quiet garbage instead of an error.
- **`xxd` is not universal.** It was missing from a minimal cloud image and had to be installed. The Python path needs only the standard library.

## 10. Open items
- [Unverified] The zip members are dated 2023-04-24, which suggests the room was reused from an earlier HTB release. Not checked against HTB's catalog.
- The 565 bytes of filler before the flag were read but not analysed for hidden content (acrostic, whitespace, stego). The flag did not depend on them.
- CyberChef's **Magic** auto-detection was not tested against `output.txt`, so it is not established whether it finds all five layers unaided.
- The §3 base64 group-lead tell is derived from the encoding math and measured on this one sample only. It has not been checked against other tools' output (for example URL-safe base64 or line-wrapped base64 every 76 characters).

## Cross-references
- [[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery]] — SecFest'26 sibling; source of the §7a kill-chain table format
- [[HTB-SecFest26-Stolen-Variables-Frontend-Embedded-IAM-Key-CloudTrail-Enumeration-DynamoDB-Scan]] — SecFest'26 sibling

## Change Log
- 2026-10-29 — Note created. Full solve: artifact inventory with hashes, the five-transform pipeline with its size ladder and per-layer entropy, layer-identification tells (charset, length, measured base64 group-lead characters), the encoding-vs-encryption section, shell/Python/CyberChef reproductions with the round-trip proof, the ATT&CK catalog with honest-scope callout, a Lockheed Martin Cyber Kill Chain mapping of the technique class (§7a, added on request), detections, method notes, and open items.
- 2026-10-29 — Finalized metadata from the platform page: difficulty `very easy`, points `800`, `solves: 28`, scenario text filled in, and real-UTC `created`/`updated` stamps; all draft placeholders removed.
