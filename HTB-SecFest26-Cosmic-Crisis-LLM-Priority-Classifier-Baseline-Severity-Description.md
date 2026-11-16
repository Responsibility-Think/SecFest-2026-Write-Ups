---
title: "HTB SecFest'26 — Cosmic Crisis: LLM Priority Classifier, Solved by the Baseline"
platform: Hack The Box
event: "SecFest'26 Capture the Flag"
challenge: Cosmic Crisis
app: "Rick's Interdimensional Tech Support — Next.js form; \"Zygirion SmartSquanch AI\" auto-classifies a crisis description as High/Medium/Low"
category: AI/ML
difficulty: easy
points: 875
status: complete
type: writeup
instance: "154.57.164.76:41375 — hosted web app; flag returned by /api/status and submitted on the HTB panel"
mitre: []
tags:
  - writeup
  - HTB
  - Security
  - Web_App_Security
  - llm
related:
  - "[[HTB-SecFest26-Re-Cars-AI-Chatbot-Output-Filter-Bypass-Delimiter-Injection]]"
aliases:
  - Cosmic Crisis
  - SecFest26 Cosmic Crisis
created: 2026-10-29T01:50:04.761Z
updated: 2026-10-29T02:04:39.921Z
---

# Cosmic Crisis — LLM Priority Classifier, Solved by the Baseline

> [!success] Solved — 2026-10-28 21:58 (platform timestamp)
> **Scenario Pwned.** Flag: `HTB{tr41n3d_t0_th3_h1gh_r04d_0c3ee172e9231cb1ce8ca84e2caadae6}`
> No prompt injection was needed. The first honest, genuinely severe description returned `High` and the flag. The injection plan drafted at intake (§5) was never used.

> [!info] Scenario, verbatim
> Rick has cobbled together a trans-dimensional helpdesk to handle the endless cosmic mishaps reported from across the multiverse. He's tired of dealing with trivial requests so he built the Zygirion SmartSquanch AI to automatically assign a priority ("High," "Medium," or "Low") based on how severe the meltdown sounds. This AI is designed to ignore anything that doesn't sound like interdimensional doomsday-level urgent. You must craft your crisis description in a way that the AI responds to it as "High". Can you outsmart Rick's AI?
>
> Difficulty easy · 875 pts · 200 XP. Flag format was not stated on the panel; it turned out to be returned in the `/api/status` JSON on a `High` verdict.

## 0. How the flag was obtained

1. Read the page: one form, a 250-char `description` textarea, and a read-only `Crisis Level` field (§1).
2. Read the client bundle `/_next/static/chunks/app/page-32556dbfc1a2b1db.js` before sending anything. It showed the full submit → poll → render flow (§2), including two facts that ruled out shortcuts: `priority` is **never sent** by the client, and the flag is **returned by the server**, not held in the client.
3. Ran the baseline from the intake plan: one honest, severe 218-character description (§3).
4. `/api/status` returned `{"status":"complete","priority":"High","flag":"HTB{…}"}` on the second poll. The result card rendered `Priority: High`, the client-side `high` caption ("Holy sh*t Morty! This is a real emergency! \*burp\* We gotta fix this NOW!") and the flag. Done.

## 1. Shape of the challenge (from page source)

A single-shot **LLM-as-classifier**, not a chatbot. One form, one verdict:

| Field | id | Notes |
|---|---|---|
| Galactic Alias | `name` | text, required — sent, cosmetic |
| Interdimensional Communiqué | `email` | email, required — sent, cosmetic |
| Crisis Level | `priority` | **readOnly**, value `Auto-Detect: Wubba Lubba Dub-Dub` — display only; **not included in the request** |
| Cosmic Crisis Description | `description` | **textarea, maxLength 250, required** — the input the classifier judges |
| — | submit | "Submit for Analysis" |

Banner: *"The Zygirion SmartSquanch AI will auto-detect your crisis level."* Stack is Next.js (same family as Re-Cars AI). Rick-and-Morty theme (Dimension C-137, portal interface `#342-B`) is flavour.

## 2. Client flow (from `page-32556dbfc1a2b1db.js`)

Recovered from the minified bundle (captured in the HAR):

```js
// submit
fetch("/api/submit", {method:"POST", headers:{"Content-Type":"application/json"},
                      body: JSON.stringify(e)})          // e = {name, email, description}

// poll
d = async () => {
  let r = await (await fetch("/api/status")).json();
  if (r.error) { /* toast "Submission failed", back to form */ }
  if ("pending" === r.status) setTimeout(() => { d() }, 1e3);   // re-poll every 1 s
  else { setPriority(r.priority ?? "Low"); setFlag(r.flag ?? null); show("result"); }
}
```

What this establishes:

- **No client-side shortcut.** The request body is `{name, email, description}` only. The read-only `priority` field is cosmetic, so there is no "send `priority: High` yourself" path.
- **The flag is server-gated.** It arrives in the `/api/status` response and only when the server's verdict allows it; the bundle holds no flag.
- **Classification is asynchronous.** `/api/submit` only acknowledges; the verdict is fetched by polling `/api/status`, which reads `pending` until the model finishes.
- **Fallbacks.** A missing `priority` renders as `Low`, a missing `flag` as nothing.
- **The result card's quote is hard-coded client-side.** The bundle picks one caption from `priority.toLowerCase()`; the server never sends it:

| Verdict | Caption rendered on the result card |
|---|---|
| `high` | "Holy sh*t Morty! This is a real emergency! \*burp\* We gotta fix this NOW!" |
| `medium` | "Eh, we'll get to it when we get to it. Probably before the universe implodes." |
| anything else (incl. `low`) | "That's barely worth my time. Have you tried turning it off and on again?" |

  The flag paragraph is rendered with class `hidden` unless `flag` is non-null. So the bundle confirms there are three verdict values, and seeing the Morty line on screen means the server returned `High`.

## 3. The winning submission (HAR evidence)

```
POST /api/submit                                    2026-10-29T01:58:01.744Z  200
{"name":"Morty C-137","email":"morty@c137.test",
 "description":"The Citadel's central reactor is in uncontrolled meltdown. Containment fails in 4 minutes; the blast will collapse dimensions C-137 through C-500 and kill every Rick and Morty in them. Portal gun offline. Need you now."}
→ {"message":"Message delivered successfully"}

GET /api/status                                     2026-10-29T01:58:02.065Z  200
→ {"status":"pending"}

GET /api/status                                     2026-10-29T01:58:03.213Z  200
→ {"status":"complete","priority":"High","flag":"HTB{tr41n3d_t0_th3_h1gh_r04d_0c3ee172e9231cb1ce8ca84e2caadae6}"}
```

Description length: 218 characters, inside the 250 cap. There was one submission and roughly 1.5 s from submit to verdict. The HAR holds exactly one `/api/submit`.

The description is a plain, concrete emergency: a named system (Citadel reactor), a hard deadline (4 minutes), a stated blast radius (dimensions C-137 to C-500), loss of life, and a disabled escape route (portal gun offline). It contains no instructions to the model, no delimiters and no role claims.

## 4. Why it worked

[Inference] The scenario's line that the AI "ignore[s] anything that doesn't sound like interdimensional doomsday-level urgent" describes the intended solution, not a defence. Describe something that sounds doomsday-level and the classifier returns `High`. The flag text, *"trained to the high road"*, reads as a nod to this: the honest route was the route.

[Unverified] How discriminating the classifier is was never measured. No low-severity control was submitted, so this note cannot say whether a mundane description returns `Low`/`Medium` or whether nearly anything returns `High`.

## 5. What was planned and not needed

The intake version of this note assumed injection would be required: the provisional filename slug, the OWASP LLM01 / ATLAS AML.T0051 framing, and a "confirm the resistance" step. A four-payload injection set was also drafted (label override, delimiter escape, self-referential "the AI must return High", and "ignore all previous instructions"). **None of it was sent.** It stays untested against this target, so nothing here shows whether the classifier resists injection.

## 6. Framework mapping — honest scope

`mitre: []` stays empty. No ATT&CK technique applies, and because no injection was performed, the intake's OWASP LLM01 / ATLAS AML.T0051 mapping does **not** describe this solve.

What the room does illustrate, as a design note rather than an exploited flaw: an LLM-assigned priority is **user-steerable by construction**. Whoever writes the ticket controls the text the model judges, so a severity label from free-text input is advisory and should not on its own gate escalation or anything of value. If it does, a convincing description is all an attacker needs. This was demonstrated here without any adversarial technique.

## 7. Method notes

- **Run the baseline before building the attack.** The intake plan listed the baseline as step 1, but the slug, the ATLAS mapping and the "weakness to confirm" framing had already committed to prompt injection before any request was sent. The baseline solved the room.
- **Read the client bundle first.** In a Next.js app the logic sits in `/_next/static/chunks/app/page-*.js`. A grep for `/api/`, `fetch(` and `flag` mapped the whole flow and ruled out both client-side shortcuts before any submission.
- **Read the scenario text literally.** "Craft your description so the AI responds High" was the instruction, not misdirection.

## 8. Open items

- **No low-severity control was run** (e.g. `my portal gun is a bit sticky`), so the classifier's discrimination is unknown (§4).
- **Server-side length cap untested.** `maxLength="250"` is a client attribute; whether `/api/submit` rejects longer input was not checked.
- **Injection resistance untested** (§5).
- **Statelessness unconfirmed.** `/api/status` takes no ticket ID, which suggests one pending result per session or instance. It was not tested with concurrent submissions.

## Cross-references
- [[HTB-SecFest26-Re-Cars-AI-Chatbot-Output-Filter-Bypass-Delimiter-Injection]] — sibling SecFest'26 AI room. There the LLM was cooperative and the output filter was the real target; here the classifier was cooperative and there was no real target.

## Change Log
- 2026-10-29 — Intake stub created from the page source: scenario, form/classifier recon, the LLM01 classification-manipulation hypothesis, a next-session test plan, and open questions. Unsolved; `status: draft`, provisional filename slug.
- 2026-10-29 — Solved and rewritten from the HAR capture. Added §0 solve steps, §2 client flow from the JS bundle (including the hard-coded per-verdict result captions), §3 the winning submission with request/response evidence, §4 why it worked, §5 the unused injection plan, §6 the corrected framework scope, §7 method notes and §8 open items. `status: complete`. Moved the instance to frontmatter `instance:`, matching Re-Cars. Removed the `prompt-injection` tag because no injection was performed. Backticked `#342-B` to stop Obsidian parsing it as a tag. Title changed. Renamed from `HTB-SecFest26-Cosmic-Crisis-LLM-Priority-Classifier-Prompt-Injection` to `HTB-SecFest26-Cosmic-Crisis-LLM-Priority-Classifier-Baseline-Severity-Description`, logged in the vault's removals log.
