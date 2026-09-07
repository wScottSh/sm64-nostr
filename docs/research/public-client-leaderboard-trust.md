# Trust Semantics of Public-Client Leaderboards / Witnessed-Attestation Systems (Model B)

Research findings for GitHub issue #22 (Wayfinder RESEARCH ticket). Part of #4. Blocks the key-provenance decision (#10). Companion to #9 (private-binary threat model); this is the **public-ROM / ephemeral-key** case.

- **Repo:** wScottSh/sm64-nostr — SM64 C decompilation building an N64 ROM that self-signs a Nostr event (a leaderboard entry) on star completion and renders it as a QR.
- **Model B ("ephemeral-key" provenance):** the ROM is potentially **PUBLIC** and the signing key is **ephemeral / throwaway**. The in-game BIP-340 Schnorr signature therefore proves only **structural validity** (a well-formed Nostr event exists), *not who produced it or whether the achievement is real*. Provenance is intended to ride on **operational control + an out-of-scope companion/operator app** that publishes an associating event.
- **Scope:** map the **trust landscape** — what a leaderboard verifier can ACTUALLY trust when the client is fully in the adversary's hands, the attacks, and the **minimal companion/operator control** that makes an event meaningful rather than spoofable. This is PLANNING/SPEC work: **not** an implementation, **not** a go/no-go call.
- **Method:** primary sources — speedrun.com rules, Twin Galaxies/MAME docs, RFC 3161, OpenTimestamps, IETF CT (RFC 6962), academic witnessing/forensics literature. Ackoff solve/resolve/**dissolve** lens.

> **Note on verification (per working discipline):** claims below are tied to named primary sources with URLs. Where a source could not be fetched firsthand this session it is flagged inline as *unverified-firsthand* — the fact came from the search index or a secondary page, not the primary document body. No inference is presented as a checked fact.

---

## 0. The one invariant that dominates everything

**A signature from a public client with an ephemeral key authenticates the KEY, not the CLAIM — and the key is worthless as an identity because anyone can mint one.** Model B's in-game signature has essentially **zero provenance value on its own**. This is the mirror image of the #8/#9 invariant (a key in a public self-signing binary is extractable): here we *concede* extractability and go further — the key is *designed* to be throwaway, so even a perfectly-hidden key would not help, because the verifier has no reason to believe *this* key belongs to a legitimate player rather than a forger.

Nostr makes this precise: a Nostr event (NIP-01) is authenticated **solely** by a BIP-340 Schnorr signature over the event id on secp256k1. Its identity is "whoever holds the private key," full stop; the protocol has no notion of "this key may only sign truthful achievements." (NIP-01: https://github.com/nostr-protocol/nips/blob/master/01.md ; BIP-340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

**Corollary:** in Model B, *all* provenance must come from **outside the game client** — from an operator, a witness, a server, or a human moderator. The entire research question is therefore: *what is the minimal external structure that converts a structurally-valid event into a trustworthy one?* Every comparable system below answers the same question, because every one of them assumes **the client is in the adversary's hands.**

---

## 1. What a public-client event can and cannot prove (the residual-trust floor)

| The event proves… | The event does NOT prove… |
|---|---|
| A **well-formed** Nostr event exists (valid Schnorr sig over the id) | That the signer is a legitimate player (ephemeral key = no identity) |
| The payload was **not mutated** after signing (integrity) | That the achievement described actually happened in a real playthrough |
| Whoever signed **held the key at signing time** | That only one such key exists, or that the operator controls it |
| (with a timestamp anchor, §5) that the data **existed before time T** | *When/where/by-whom* the game was actually played |

This is exactly the **RFC 3161 / OpenTimestamps residual-trust floor** (§5): a cryptographic artifact binds *structure* and possibly *time*, but is silent on *content truth* and *identity*. Every comparable system layers a **human, operational, or witness** mechanism on top of that floor to recover trust.

---

## 2. Comparable systems: how trust is established when the client is untrusted

### 2.1 speedrun.com — video proof + human moderation (the dominant model)

speedrun.com does not trust the client at all; it trusts **evidence + moderators**.

- **Video is the substrate of trust.** The video must be of "reasonable viewing quality and stable framerate to clearly see everything in the game." For "highly competitive times in highly competitive games, moderators may impose additional proof requirements such as demonstration of skill over a period of time via streaming or a lengthy video showing numerous attempts." — speedrun.com Moderation Rules, https://www.speedrun.com/support/learn/moderation-rules *(unverified-firsthand: page returned HTTP 403 to the fetcher; quotes are from the search index of that page.)*
- **Anti-tamper heuristics are explicit.** "Runs recorded with an external video camera will not be verified"; "audio recordings help to detect splicing"; "Splicing is editing segmented runs to one continuous video looking like an RTA. You can't actually verify … a run that doesn't have a working video, as that's indistinguishable from a splice." Some categories "require proof of button presses in the form of an input display or hand cam … full displayed game resets, settings displayed at the start or end of a run" to defeat RNG manipulation. — speedrun.com forums (community-normative), https://www.speedrun.com/forums/speedrunning/rbrne and https://www.speedrun.com/forums/speedrunning/mauz5
- **Trust ultimately rests on fallible humans.** Moderators are "generally provided 21 days" to handle a submission; "Preferential treatment … is forbidden." — Moderation Rules (as above).
- **The model's documented failure mode:** an academic forensic framework observes that verification "remains slow, inconsistent, and reliant on informal expertise," and that "fraudulent runs have gone undetected for years, allowing perpetrators to gain fame and financial benefits." — *Tracer: A Forensic Framework for Detecting Fraudulent Speedruns from Game Replays*, arXiv 2509.10848, https://arxiv.org/html/2509.10848v1

**Lesson for Model B:** the trust anchor is **out-of-band evidence + a trusted human/institution**, never the client. The signature is at best a convenience (integrity/dedup), not the source of truth.

### 2.2 Twin Galaxies / MAME — witnessed replay + reference implementation + forensic review

Arcade high-score attestation is the closest analog to "an emulated client in the adversary's hands," and its history is a live demonstration of the Model-B attack.

- **The evidence is a replayable input recording, not a score claim.** For MAME submissions the key evidence is the **INP file**, which "records the player's inputs and allows for a score to be played back," and "officially recognized INP files must originate from a special version of MAME known as **WolfMAME**." — Twin Galaxies MAME Submission Rules, https://www.twingalaxies.com/wiki_index?title=Guidelines%3AOfficial-MAME-Platform-Submission-Rules-and-Guidelines *(unverified-firsthand: wiki returned HTTP 403; requirement corroborated across the search index and speedrun.com/marpirc guides below.)*
- **WolfMAME = a constrained reference client** that "attempts to force people to play and record games as they had to be played … without an autofire mechanism," and "contains limitations on some general MAME options that may be unfairly used." But it is explicitly **"not completely tamper-proof"**; verification "relies on manual review and detection rather than absolute technical prevention." — shmups/marpirc guides, https://shmups.system11.org/viewtopic.php?p=167242 and http://www.marpirc.net/viewtopic.php?t=11580
- **The canonical spoof + how it was caught (Billy Mitchell):** disputed Donkey Kong recordings showed "MAME signatures" (direct-feed capture artifacts) rather than "arcade signatures"; Twin Galaxies and Mitchell's own techs "could not reproduce the same signatures … on genuine arcade machines," so in 2018 TG removed all his scores and banned him. — Sports Illustrated, https://www.si.com/more-sports/2018/04/12/king-kong-star-stripped-high-scores ; technical analysis, https://perfectpacman.com/2022/09/06/new-technical-analysis/

**Lesson for Model B:** even a **constrained reference client + deterministic replay** does not by itself prevent fraud; trust came from (a) requiring a *replayable transcript*, (b) a *reference environment* whose artifacts are hard to fake, and (c) *forensic human review comparing signatures to a known-authentic baseline*. The determinism (INP replay) is the technical half; the institution is the trust half.

### 2.3 Honor + witness leaderboards (chain-of-custody model, from anti-doping)

Where the "client" (the athlete/sample) is inherently untrusted, sports establishes trust with a **witnessed chain of custody**:

- A trained **Chaperone/DCO** performs "notification … accompanying and observing the Athlete; and witnessing and verifying the provision of the … Sample." Collectors "witness urine collection to help prevent samples from being adulterated or substituted." — WADA/USADA, https://www.usada.org/sample-collection-process/
- **Chain of Custody** = "the sequence of individuals or organisations who have responsibility for the custody of a Sample … until … delivered to the laboratory," documented on signed forms and enforced with "tamper evident seals." — WADA, https://www.wada-ama.org/en/resources/sample-collection and https://www.wada-ama.org/sites/default/files/resources/files/instructions_wada_chain_of_custody_form_v4_en.pdf

**Lesson for Model B:** trust = **a trusted witness present at the moment of production + a tamper-evident custody trail from production to record.** The companion/operator app is exactly a "chaperone": it witnesses the run and seals the evidence before it reaches the leaderboard.

### 2.4 e-sports / online multiplayer — server-authoritative state (dissolve the client's authority)

Competitive games do not try to make the client honest; they **remove its authority to assert results.**

- "Server-authoritative systems where the client only sends intent … and the server decides what really happens." "Server authority assumes the machine is lying and refuses to trust its reports." This "kills entire exploit classes outright — speed hacks, teleport, item duplication, instant-kill hit injection — because the cheat never gets to assert state in the first place." — AccelByte, https://accelbyte.io/blog/server-authoritative-logic-to-prevent-cheating
- **But server authority has hard limits** exactly where the game can't see: "a server that owns the game state still can't see a wallhack that only changes what the player's GPU renders … an aimbot running on a second machine reading the screen with a capture card." Hence a "layered approach" with kernel anti-cheat + server authority + backend analytics. — https://crux.supercraft.host/blog/server-authoritative-anti-cheat-backend/ ; systematic review: *A Systematic Review of Technical Defenses Against Software-Based Cheating in Online Multiplayer Games*, arXiv 2512.21377, https://arxiv.org/html/2512.21377v1 *(unverified-firsthand: review body not fetched; cited from search index.)*

**Lesson for Model B:** the strongest move is to **not let the client be authoritative** at all — the trusted party (operator/server) decides what counts. This is the "dissolve" answer (§6) and directly matches the ticket's "companion/operator app publishes the associating event."

---

## 3. Cryptographic witnessing / notarization schemes (what they add and their trust floor)

These are the tools that could give the operator/witness layer teeth. Each binds *something* cryptographically, but **none manufactures provenance from a public client alone.**

### 3.1 Trusted timestamping — RFC 3161 (TSA)

- A TSA binds a **hash to a time**: it supports "assertions of proof that a datum existed before a particular time," including "a trustworthy time value" and "a unique integer for each … token." — RFC 3161, https://www.rfc-editor.org/rfc/rfc3161.txt
- **Explicit non-attestation (the residual-trust floor):** the TSA is "not to examine the imprint being time-stamped in any way (other than to check its length)" and "not to include any identification of the requesting entity"; "The time-stamp request does not identify the requester, as this information is not validated by the TSA." — RFC 3161, ibid.
- **Trust cost:** the token "depend[s] entirely on the TSA's PKI certificate chain"; certs expire (typically 1–3 yrs) requiring re-timestamping. — RFC 3161 §4; OriginStamp, https://originstamp.com/en/blog/reader/blockchain-timestamp

### 3.2 OpenTimestamps (blockchain proof-of-existence)

- Anchors a hash into Bitcoin: "A timestamp proves that some data existed prior to some point in time," verifiable "without relying on any central authority" via a Merkle path to a block header. — https://opentimestamps.org/
- **Explicit non-attestation:** "the timestamp only establishes *when* data existed; it reveals nothing about *who* created it or *whether the data is truthful or legitimate*." — https://opentimestamps.org/ (as summarized firsthand) ; created by Peter Todd, https://github.com/opentimestamps

**Use in Model B:** a timestamp anchor defeats **backdating / retroactive fabrication** ("I set this record last year") and lets a later operator event *commit* to a play trace it already saw — but it adds **zero** identity or truth. It is a complement to witnessing, never a substitute.

### 3.3 Certificate Transparency — public append-only logs + gossip (RFC 6962)

- Detection-not-prevention model: "Violation of the append-only property is detected by global gossiping … everyone auditing logs comparing their … Signed Tree Heads. As soon as two conflicting [STHs] for the same log are detected, this is cryptographic proof of that log's misbehavior." — RFC 6962, https://www.rfc-editor.org/rfc/rfc6962
- **Trust model:** does not stop a bad log; makes misbehavior **publicly and undeniably detectable after the fact.**

**Use in Model B:** publishing all accepted leaderboard events to a public, append-only, gossiped log makes **operator equivocation** (showing different leaderboards to different people, or silently editing history) detectable. It keeps the *operator* honest, which is the residual trust once provenance is offloaded to the operator.

### 3.4 Decentralized witness cosigning — CoSi ("honest or bust")

- CoSi ensures "every authoritative statement is validated and publicly logged by a diverse group of witnesses before any client will accept it," so that a compromised authority key still cannot be used in secret: it "guarantees [the statement's] exposure to public scrutiny, forcing secrecy-minded attackers to risk that the compromise will soon be detected." Scales to "over 8,000 distributed witnesses" cosigning "in under two seconds." — Syta et al., *Keeping Authorities "Honest or Bust" with Decentralized Witness Cosigning*, IEEE S&P 2016, arXiv 1503.08768, https://arxiv.org/abs/1503.08768

**Use in Model B:** if provenance rides on an operator key, CoSi-style **co-signing by independent witnesses** raises the bar from "trust one operator" to "trust that a threshold of witnesses all validated this event," and makes a rogue/compromised operator visible. This is the strongest *decentralized* version of the operator layer.

---

## 4. The Model-B attack surface (what breaks, and the minimal control that closes it)

Every row assumes the ROM is public and the runtime key is ephemeral/throwaway.

| # | Attack | Why the in-game signature does NOT stop it | Minimal companion/operator control that closes it | Precedent |
|---|---|---|---|---|
| A1 | **Forged event (mint your own key)** — attacker generates an ephemeral key, signs a fake achievement | Sig authenticates *a* key, and anyone can make a key (§0) | Only events **witnessed/re-signed by the operator** count; ignore un-associated events | speedrun mod verification (2.1); server-authoritative (2.4) |
| A2 | **Score/payload tampering** — edit stars/time before signing | Client is fully attacker-controlled; it signs whatever it's told | Operator must **witness the actual playthrough** (video/telemetry) before associating, not trust the payload | Twin Galaxies INP replay (2.2); WADA chaperone (2.3) |
| A3 | **Replay / duplication** — resubmit a genuine event many times | Sig stays valid on copies | Operator dedup on event id + **timestamp/nonce**; append-only log | CT append-only (3.3); RFC 3161 unique serial (3.1) |
| A4 | **Backdating / retroactive fabrication** — claim an old record | Nothing in the event binds real time | **Timestamp anchor** (RFC 3161 / OTS) committed by the operator at witness time | RFC 3161, OpenTimestamps (3.1–3.2) |
| A5 | **Emulator/TAS/splice** — superhuman or spliced "playthrough" fed to the witness | The game can't tell; a naive operator would associate it | **Reference-environment + replay/forensic review** (deterministic transcript, artifact checks, input display) | WolfMAME + forensics (2.2); Tracer (2.1) |
| A6 | **Operator compromise / equivocation** — the trusted operator is the single point of failure | Provenance now *is* the operator key; one compromise forges everything | **Public append-only log + gossip** and/or **witness cosigning** so operator misbehavior is detectable / requires collusion | CT (3.3); CoSi (3.4) |

**Reading of the table:** the in-game signature closes **none** of A1–A6 by itself. A **single trusted operator that witnesses the run and re-signs** closes A1–A5. Closing A6 (keeping the operator honest) requires **transparency logging and/or witness cosigning.**

---

## 5. The residual-trust stack (synthesis)

Trust in a Model-B leaderboard is a **layered stack**, each layer recovering something the layer below cannot provide:

1. **In-game Schnorr signature** → integrity + well-formedness only. (Floor; §0–§1.)
2. **Timestamp anchor** (RFC 3161 / OTS) → "existed before T"; defeats backdating (A4). Still no identity/truth.
3. **Operator witnessing + re-signing** (the companion app) → binds the event to a *witnessed real playthrough* and to an *accountable identity*; this is where provenance actually lives. Defeats A1–A3, A5. (Analog: WADA chaperone, speedrun moderator, server authority.)
4. **Forensic/reference-environment review** → raises the cost of A5 (TAS/splice/emulator artifacts). (Analog: WolfMAME + Tracer.)
5. **Public append-only log + gossip and/or witness cosigning** → keeps the operator honest; defeats A6. (Analog: CT, CoSi.)

**The minimum viable trustworthy configuration** for this tech demo: **layers 1 + 3** (game signs for integrity; a single trusted operator witnesses the run and publishes the associating/re-signed event). That already makes an event *meaningful rather than spoofable* to anyone who trusts the operator. Layers 2, 4, 5 harden against backdating, sophisticated fabrication, and operator compromise respectively, and can be added incrementally.

---

## 6. Ackoff SOLVE / RESOLVE / DISSOLVE

Russell Ackoff, *The Art of Problem Solving* (Wiley, 1978): **dissolve** = redesign the system so the problem cannot arise.

- **SOLVE (make the in-game signature trustworthy on its own):** harden the key / prove it's the "real" key. Verdict: **impossible in Model B by construction** — the key is ephemeral and the ROM public, so there is no "real" key to authenticate (§0). Even the #8/#9 hardening landscape only yields speed bumps, and Model B *concedes* extraction anyway. Dead end.
- **RESOLVE (good-enough operator-mediated trust):** accept that the game signature is only integrity, and **layer a trusted operator + evidence** on top (§5, layers 1+3, optionally +2/+4). This is the pragmatic tech-demo answer and matches every comparable system (speedrun, TG, WADA, e-sports): *trust the institution/witness, not the client.* Blast radius = "trust this one operator."
- **DISSOLVE (remove the client's authority to assert results):** make the client **non-authoritative** — it only produces *intent/evidence* (a witnessed transcript or challenge/response), and a **trusted operator/server + transparency log + optional witness cosigning** decides what counts and publishes it. The public ROM and ephemeral key then carry **no trust weight at all**, so their spoofability stops mattering. This is the server-authoritative move (2.4) generalized, and it is the strongest framing: *the problem "the client can lie" is dissolved by never letting the client's word be the record.*

**The dissolve is the same conclusion #8/#9 reached from the other direction:** stop requiring a client-held secret to be secret / stop letting the client be the source of truth. Model B is *already* an instance of dissolving — it explicitly offloads provenance to the operator. This ticket's contribution is to name **the minimal operator structure that makes that offload real:** witness-at-production (A2/A5) + associate/re-sign (A1) + dedup/timestamp (A3/A4) + transparency/cosigning to keep the operator honest (A6).

---

## 7. Honest bottom line

1. **A public-client ephemeral-key signature has ~zero standalone provenance value.** It proves structural validity and integrity, nothing about identity or truth (§0–§1). This is a corollary of what Nostr signatures mean + the fact that anyone can mint a key — not a tooling gap.
2. **Every comparable system that works with an untrusted client puts trust OUTSIDE the client:** speedrun.com (video + human mods), Twin Galaxies/WolfMAME (replayable transcript + reference env + forensic review), anti-doping (witnessed chain of custody), e-sports (server-authoritative). None trusts the client's self-report.
3. **Cryptographic witnessing tools sharpen but never replace the human/operational layer.** RFC 3161 and OpenTimestamps *explicitly* attest time-only and disclaim content/identity; CT and CoSi keep *authorities* honest, they don't validate *claims*. They are complements to a witness, not a substitute for one.
4. **The minimal control that makes a Model-B event meaningful:** a **trusted operator/companion app that (a) witnesses the actual playthrough, (b) associates/re-signs the event under an accountable identity, and (c) dedups + timestamps it.** That closes forgery, tampering, replay, backdating, and (with reference-env/forensics) most fabrication.
5. **To keep the operator itself honest** (the new single point of failure), add a **public append-only log + gossip and/or witness cosigning** — otherwise "trust is offloaded to the operator" just relocates the whole trust problem to one key.
6. **Ackoff:** SOLVE is impossible here; the design is already a DISSOLVE (client non-authoritative), and the deliverable is the *minimal operator structure* that realizes it.

*This document maps the landscape only. It is not an implementation and not a go/no-go recommendation. It informs the key-provenance decision (#10).*

---

## Sources

- NIP-01 (Nostr event/signature semantics): https://github.com/nostr-protocol/nips/blob/master/01.md
- BIP-340 (Schnorr signatures): https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- speedrun.com Moderation Rules: https://www.speedrun.com/support/learn/moderation-rules *(HTTP 403 to fetcher; quoted via search index)*
- speedrun.com Site Rules: https://www.speedrun.com/support/learn/site-rules
- speedrun.com forums (verification/splicing norms): https://www.speedrun.com/forums/speedrunning/rbrne , https://www.speedrun.com/forums/speedrunning/mauz5
- Tracer (speedrun forensics), arXiv 2509.10848: https://arxiv.org/html/2509.10848v1
- Twin Galaxies MAME Submission Rules: https://www.twingalaxies.com/wiki_index?title=Guidelines%3AOfficial-MAME-Platform-Submission-Rules-and-Guidelines *(HTTP 403; corroborated via search index + guides)*
- WolfMAME/INP context: https://shmups.system11.org/viewtopic.php?p=167242 , http://www.marpirc.net/viewtopic.php?t=11580
- Billy Mitchell / Twin Galaxies ruling: https://www.si.com/more-sports/2018/04/12/king-kong-star-stripped-high-scores ; technical analysis: https://perfectpacman.com/2022/09/06/new-technical-analysis/
- WADA/USADA chain of custody & witnessed collection: https://www.usada.org/sample-collection-process/ , https://www.wada-ama.org/en/resources/sample-collection , https://www.wada-ama.org/sites/default/files/resources/files/instructions_wada_chain_of_custody_form_v4_en.pdf
- Server-authoritative anti-cheat: https://accelbyte.io/blog/server-authoritative-logic-to-prevent-cheating , https://crux.supercraft.host/blog/server-authoritative-anti-cheat-backend/
- Systematic review of anti-cheat defenses, arXiv 2512.21377: https://arxiv.org/html/2512.21377v1 *(unverified-firsthand)*
- RFC 3161 (Time-Stamp Protocol): https://www.rfc-editor.org/rfc/rfc3161.txt
- OpenTimestamps: https://opentimestamps.org/ , https://github.com/opentimestamps
- RFC 6962 (Certificate Transparency): https://www.rfc-editor.org/rfc/rfc6962
- CoSi — Syta et al., "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning," IEEE S&P 2016, arXiv 1503.08768: https://arxiv.org/abs/1503.08768
- Ackoff, *The Art of Problem Solving*, Wiley 1978.
