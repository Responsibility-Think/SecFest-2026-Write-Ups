---
title: "HTB SecFest'26 — Me is Mey: Non-Injective Pre-Hash Byte Rotate → SHA-256 Second Preimage"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
challenge: Me is Mey
app: "`server.py` — TCP prompt that prints the custom hash of `ready_play_one!` and returns the flag for any different hex-encoded message with the same digest; the custom hash is SHA-256 over a broken per-byte \"rotate\""
category: crypto
difficulty: medium
points: 875
type: writeup
status: complete
instance: "154.57.164.74:35036 — Docker, spawned for all team members; the card labels it http:// but the service is a raw TCP prompt — single flag, returned by the live server"
mitre:
  - T1190
  - T1553
tags:
  - writeup
  - HTB
  - Security
  - Cryptography
  - hash-collision
  - kill-chain
related:
  - "[[HTB-SecFest26-Based0x-Layered-Hex-Base64-Encoding-Reversal]]"
  - "[[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery]]"
aliases:
  - Me is Mey
  - SecFest26 Me is Mey
created: 2026-10-29T05:35:13.112Z
updated: 2026-11-15T20:05:02.392Z
---

# Me is Mey — Non-Injective Pre-Hash Byte Rotate → SHA-256 Second Preimage

> [!success] Solved — 2026-10-29 01:32 (platform timestamp)
> **Scenario Pwned.** Flag: `HTB{sh4256_bu7_w17h_4_7w157_83f023_c4n_c4u5e_c011i51on5}`, which reads "sha256 but with a twist before can cause collisions."
> crypto · medium · 875 pts · 300 XP per team. One forged message sent, first attempt. SHA-256 was never attacked: the collision happens in the byte transform before it (§2).

> [!info] Scenario, verbatim
> For the concluding challenge, you revisit the creator's final statement, "Only the one who is me can be me". After careful consideration, you deduce that these words refer to the creator's personal signature. The key to unlocking the final challenge lies in accurately reproducing this signature.

## 0. How the flag was obtained

1. Unzipped the handout → `crypto_me_is_me/server.py` (1,059 B). No `secret.py`.
2. Read `server.py`: digest = `sha256(rotate(m))`. The flag is returned when a hex-encoded message hashes to the same digest as `ready_play_one!` **and** differs from it byte-for-byte.
3. **Spotted the defect: `rotate` is `(b >> 4) | (b << 3)`. The shifts sum to 7, not 8, so it is not a rotation.** Input bits 0 and 7 are ORed onto the same output bit.
4. Enumerated all 256 byte values: 128 distinct outputs. 64 of them have exactly three preimages. Every odd ASCII byte `b` shares its output with `b | 0x80` and `b ^ 0x81`.
5. Forged `ready_play_one!` with index 1 `e` (`0x65`) → `0xe5`. Hex `72e56164795f706c61795f6f6e6521`, same digest, different bytes.
6. Proved it locally against the real `server.py` with a stub `secret` module: the original message → `Conditions not satisfied!`, the forgery → stub flag. Repeated behind a local TCP socket with the solve script. A fake HTTP responder made the script stop without sending anything.
7. Live: the script confirmed the banner digest `fd9c…c582` matched the handout, sent the forgery once, printed the flag, and closed.
8. Submitted → Scenario Pwned, 01:32.

## 1. Shape of the challenge

| File | Size | SHA-256 | What it is |
|---|---|---|---|
| `a6beb08a-a21bac8b-bfa9-4bfe-91f0-64aee08eed01.zip` | 824 B | `3f40f726aa642d236db72d58a1a3d7447d7c280ccf94c217bac2afa44a99a122` | The download. Member dated 2023-01-20 20:12 |
| `crypto_me_is_me/server.py` | 1,059 B | `74861d14f469b1ebd0d3e6e191d1f6e980b31c463218e10b8038a42e1fe86523` | The live service's source, minus the `secret` module |

`server.py`, verbatim:

```python
from secret import FLAG
from hashlib import sha256


class hash():

    def __init__(self, message):
        self.message = message

    def rotate(self, message):
        return [((b >> 4) | (b << 3)) & 0xff for b in message]

    def hexdigest(self):
        rotated = self.rotate(self.message)
        return sha256(bytes(rotated)).hexdigest()


def main():
    original_message = b"ready_play_one!"
    original_digest = hash(original_message).hexdigest()
    print(
        f"Find a message that generate the same hash as this one: {original_digest}"
    )

    while True:
        try:
            message = input("Enter your message: ")
            message = bytes.fromhex(message)

            digest = hash(message).hexdigest()

            if ((original_digest == digest) and (message != original_message)):
                print(f"{FLAG}")
            else:
                print("Conditions not satisfied!")

        except Exception as e:
            print(f"An error occurred while processing data: {e}")


if __name__ == '__main__':
    main()
```

**The one structural fact:** the hash is `SHA256 ∘ rotate`. A composition is only as collision-resistant as its weakest stage. If the stage in front of SHA-256 maps two inputs to the same bytes, SHA-256 receives identical input and must return identical output. SHA-256's strength is irrelevant; the defect is entirely in `rotate`.

The task is formally a **second preimage**: given a fixed message, find a different one with the same digest. The flag calls it a collision. Either way, the work is zero hash computations against SHA-256.

## 2. The broken rotate — bit map

A true 8-bit rotate-left-by-3 is `((b << 3) | (b >> 5)) & 0xff`, and by 4 is `((b << 4) | (b >> 4)) & 0xff`. Both are bijections; rotate-left-by-3 was checked over all 256 values. The handout's shifts are 4 and 3, which add up to 7, so the two halves overlap:

| Output bit | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
|---|---|---|---|---|---|---|---|---|
| Comes from | b4 | b3 | b2 | b1 | **b0 \| b7** | b6 | b5 | b4 |

The map was checked against all 256 inputs. Two defects follow from it:

- **Bit 4 is copied twice** (output bits 0 and 7), so output bit 0 always equals bit 7. The output carries only 7 bits of information, giving at most 128 distinct values.
- **Bits 0 and 7 are ORed together.** For output bit 3 = 1 there are three inputs: (b0, b7) = (1, 0), (0, 1) or (1, 1). For output bit 3 = 0 there is only one: (0, 0).

Measured preimage classes: **64 outputs with exactly 1 preimage and 64 outputs with exactly 3** (64 + 192 = 256). This is information destroyed before the cryptographic hash ever runs.

## 3. Building the forgery

`ready_play_one!` is all ASCII, so bit 7 is clear in every byte. A byte has twins only if bit 0 is set (the byte is odd). Its two twins are then `b | 0x80` (set b7, keep b0) and `b ^ 0x81` (set b7, clear b0).

| Index | Char | Byte | Twins | | Index | Char | Byte | Twins |
|---|---|---|---|---|---|---|---|---|
| 0 | `r` | `0x72` | — | | 8 | `a` | `0x61` | `0xe0` `0xe1` |
| 1 | `e` | `0x65` | `0xe4` `0xe5` | | 9 | `y` | `0x79` | `0xf8` `0xf9` |
| 2 | `a` | `0x61` | `0xe0` `0xe1` | | 10 | `_` | `0x5f` | `0xde` `0xdf` |
| 3 | `d` | `0x64` | — | | 11 | `o` | `0x6f` | `0xee` `0xef` |
| 4 | `y` | `0x79` | `0xf8` `0xf9` | | 12 | `n` | `0x6e` | — |
| 5 | `_` | `0x5f` | `0xde` `0xdf` | | 13 | `e` | `0x65` | `0xe4` `0xe5` |
| 6 | `p` | `0x70` | — | | 14 | `!` | `0x21` | `0xa0` `0xa1` |
| 7 | `l` | `0x6c` | — | | | | | |

Ten of fifteen positions have twins, each with three valid values including the original. That gives 3¹⁰ − 1 = **59,048 forgeries**. All 59,048 were enumerated and every one matched the target digest. The sent payload is the smallest change: one byte, index 1, `0x65` → `0xe5`.

**Why the server's guard doesn't help.** `message != original_message` compares raw input bytes, but the hash compares post-`rotate` bytes. The guard enforces "different input" in exactly the space where the function is not injective, so it rules out only the one trivial answer.

Every forgery is 15 bytes. `rotate` works byte by byte and SHA-256 is length-sensitive, so a message of any other length would need a genuine SHA-256 collision.

## 4. The live instance

- **The card's `http://` label was wrong for this service.** `server.py` is an `input()` loop. The solve script reads the banner first and checks it for the handout's digest before sending anything. If the port had been an HTTP front end or a different build, the script stops with nothing sent.
- **The banner matched** (`fd9c3208…f45cc582`). The live server is the handout code with the target unchanged.
- **EOF quirk.** The bare `except Exception` in the `while True` loop catches `EOFError`. When input ends, the server loops forever printing `EOF when reading a line`. A local test without a cap produced 64 MB of it. The solve script therefore reads exactly one response and closes the socket, rather than piping into `nc` and leaving the connection half-open.
- **Shared host.** One connection to the card's `IP:PORT` only. No scanning of `154.57.164.74`.

## 5. Final payload

The forged message (hex), pasted at `Enter your message:`:

```
72e56164795f706c61795f6f6e6521
```

Manual: `nc 154.57.164.74 35036`, paste the hex, Ctrl+C after the flag prints.

The script that was run (`meismey_solve.py` on Kali; `python3 meismey_solve.py`):

```python
import socket, sys

HOST, PORT = "154.57.164.74", 35036
EXPECT  = "fd9c3208d1bc1a2678e3aaf7c3ce498ee754d112a3cbae586cb7dce7f45cc582"
PAYLOAD = "72e56164795f706c61795f6f6e6521"   # ready_play_one! with byte 1 0x65 -> 0xe5

def read_until(s, token, limit=8192):
    buf = b""
    try:
        while token not in buf and len(buf) < limit:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf

s = socket.create_connection((HOST, PORT), timeout=10)
banner = read_until(s, b"Enter your message: ").decode(errors="replace")
print(banner)
if EXPECT not in banner:
    s.close()
    sys.exit("STOP: banner does not contain the handout hash - nothing was sent. Paste this output to Claude.")
s.sendall(PAYLOAD.encode() + b"\n")
reply = read_until(s, b"Enter your message: ").decode(errors="replace")
print(reply)
s.close()
```

Live output:

```
Find a message that generate the same hash as this one: fd9c3208d1bc1a2678e3aaf7c3ce498ee754d112a3cbae586cb7dce7f45cc582
Enter your message:
HTB{sh4256_bu7_w17h_4_7w157_83f023_c4n_c4u5e_c011i51on5}
Enter your message:
```

Offline forgery and check, standard library only:

```python
from hashlib import sha256
f = lambda b: ((b >> 4) | (b << 3)) & 0xff
H = lambda m: sha256(bytes(f(x) for x in m)).hexdigest()
orig = b"ready_play_one!"
forged = bytearray(orig); forged[1] |= 0x80          # 'e' 0x65 -> 0xe5
forged = bytes(forged)
assert H(forged) == H(orig) and forged != orig
print(forged.hex())                                   # 72e56164795f706c61795f6f6e6521
```

## 6. Tools & techniques
`unzip` 6.00 · Python 3.13 (`hashlib`, `itertools.product`, `socket`, `runpy` with a stub `secret` module; run with `-I` against untrusted input) · Python 3 on Kali for the live run · `nc` (manual alternative)
Concepts: composition weakness (`SHA256 ∘ f` is only as strong as `f` is injective) · broken bit rotation (shift amounts must sum to the word width) · preimage-class enumeration over a byte map · second preimage vs collision · guard checks that compare in the wrong domain (raw input vs post-transform) · banner verification before sending to a live target

## 7. MITRE ATT&CK
- **T1190** Exploit Public-Facing Application — the reach: a network-exposed service accepting attacker-controlled input
- **T1553** Subvert Trust Controls — the effect: a forged message passes a hash-based "signature" check and is treated as the authentic one

> [!note] Honest scope of this mapping
> Both IDs were assigned without reading the live matrix pages. **T1553 is the weakest.** Its sub-techniques cover code signing, Mark-of-the-Web and installed root certificates, and none of them describes forging a custom hash. It is kept only because the room's effect, passing an authenticity check with content the owner never produced, is that technique's intent. ATT&CK has no hash-collision technique. The accurate classification is OWASP **A02:2021** Cryptographic Failures, with CWE-328 Use of Weak Hash, or CWE-327 Use of a Broken or Risky Cryptographic Algorithm for the broader home-rolled-primitive framing. The CWE IDs were assigned from knowledge and not checked against the live CWE list.

## 7a. Lockheed Martin Cyber Kill Chain

§7 names the techniques; the kill chain gives the order. Unlike a pure-encoding room, this one is a real, if tiny, attack: an offline-built forgery delivered to a live service. Almost all the work sits in phase 2.

| # | Phase | In this room | Basis |
|---|---|---|---|
| 1 | Reconnaissance | Full white-box: the handout ships the service's source; the banner discloses the target digest | `server.py`; live banner |
| 2 | Weaponization | Bit-mapped `rotate`, enumerated its 128-value image, built a one-byte forgery, proved it against the real code under a stub `secret` | §2–§3; local harness |
| 3 | Delivery | One TCP connection to `154.57.164.74:35036`; banner digest verified before the single hex line was sent | §4–§5 |
| 4 | Exploitation | The check `original_digest == digest and message != original_message` passes: `0x65` and `0xe5` collapse to the same byte before SHA-256 | live response |
| 5 | Installation | **None.** One request, one response; nothing persists | — |
| 6 | Command & Control | **None.** An interactive prompt, not an established channel | — |
| 7 | Actions on Objectives | Secret disclosure: the forged "signature" is accepted and the flag returned | live output |

> [!important] Where the chain was cheapest to break
> **Phase 4, the defect itself**, and nowhere else. Phases 1–2 are offline and invisible to the defender: with the source public, Weaponization needs no interaction with the target. Phase 3 is a single well-formed line. If `rotate` were a true rotation (shifts summing to 8), or if there were no transform at all, the forgery space would be empty. Producing one would then require a SHA-256 second preimage, which is not feasible. The only defender-visible signal sits in phases 3–4, and §8 covers it.

## 8. Detection / blue-team & fix notes
- **The fix:** do not transform input before hashing it with a home-rolled step. If a transform is genuinely needed, it must be a bijection. A rotate must use shifts summing to the word width, `((b << 3) | (b >> 5)) & 0xff`, and is verified by checking all 256 outputs are distinct, a one-line test.
- **For a real "signature", use one.** Authenticity needs a keyed MAC (HMAC-SHA-256) or a digital signature (Ed25519 / ECDSA). A bare hash of a public message proves nothing about who produced it, even when the hash is sound.
- **Compare in the domain that matters.** The guard compared raw input while the hash compared transformed bytes. Any canonicalization in front of a hash or signature that loses information turns into forgeable equivalents. [Inference] Common examples are case-folding, whitespace stripping and Unicode compatibility normalization.
- **Test for injectivity.** A property test over the transform's whole input space (256 values here) would have caught this immediately. Lossy pre-processing is invisible to tests that only check known-good inputs.
- **Detection signal.** Any accepted message that differs from the original is by definition an attack: the legitimate population for this check is a single message. Secondary signal: bytes ≥ `0x80` arriving where the expected input is ASCII.
- **Error handling.** `except Exception` inside `while True` turns client EOF into an unbounded output loop (§4). Catch `EOFError` explicitly and exit.

## 9. Method notes
- **Read the primitive's arithmetic before reaching for crypto attacks.** The name `rotate` invites trust. Summing the shift amounts (4 + 3 ≠ 8) found the bug in seconds; a SHA-256 attack was never on the table.
- **Enumerate small spaces.** A byte map has 256 inputs. Enumerating all of them gave exact preimage classes (64 × 1, 64 × 3) and turned "probably lossy" into a measured fact.
- **Prove against the real code, not a reimplementation.** Running the handout's `server.py` under a stub `secret` module tested the actual check logic, including the `message != original_message` guard, plus a negative control (the original message must fail).
- **Verify the target before sending.** The banner-digest check confirmed the live service was the handout build before the payload went out, and a fake HTTP responder confirmed the script stops when it isn't.
- **Cap local test output.** The first local run did not cap the server's output and the EOF loop wrote 64 MB. Pipe local servers through `head`, or close the connection deliberately, as the solve script does.

## 10. Open items
- [Unverified] The zip member is dated 2023-01-20, which suggests the room was reused from an earlier HTB release. Not checked against HTB's catalog.
- Whether the live service's wrapper (socat or similar) terminates the server process when the client disconnects, or leaves it in the EOF loop, was not observed.
- The challenge name is "Me is Mey" on the platform and `crypto_me_is_me` in the handout. The platform spelling is used here per the writeup standard; the "Mey" spelling was not investigated.

## Cross-references
- [[HTB-SecFest26-Based0x-Layered-Hex-Base64-Encoding-Reversal]] — SecFest'26 crypto sibling, solved 13 minutes earlier: encoding mistaken for encryption, where this room is hashing mistaken for signing
- [[HTB-SecFest26-Leaked-Linux-Memory-MSFvenom-Reverse-Shell-Pagecache-Recovery]] — SecFest'26 sibling; source of the §7a kill-chain table format

## Change Log
- 2026-10-29 — Note created. Full solve: handout source verbatim, the bit map of the broken `rotate` with measured preimage classes (64 × 1, 64 × 3), the forgery table and the full count of 59,048 forgeries (all verified), the wrong-domain guard, live-instance handling (http-label mismatch, banner-digest check, EOF loop), the payload and live output, ATT&CK with honest-scope callout, Lockheed Martin Cyber Kill Chain (§7a), fixes and detections, method notes, and open items.
- 2026-11-15 — OPSEC: analyst-machine paths in Final payload replaced with paths relative to the challenge folder (writeup standard draft v2 §11). `created` and `updated` stamped; they held an unfilled placeholder, and `created` was recovered from the file's ctime. No analytical content changed.
