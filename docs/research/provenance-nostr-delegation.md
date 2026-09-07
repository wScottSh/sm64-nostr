# Nostr-Native Provenance for an Ephemeral Client Key (delegation / attestation / timestamping)

Research findings for GitHub issue #18 (Wayfinder RESEARCH ticket).

- **Repo:** wScottSh/sm64-nostr — SM64 C decompilation building an N64 ROM that, on star completion, builds a signed Nostr event (BIP-340 Schnorr / secp256k1) and renders it as an on-screen QR code.
- **Design fork this informs:** Model A ("baked key" — per-event key embedded at build time, binary never distributed, the game's signature *is* the origin-provenance) vs. **Model B ("ephemeral key" — game mints a THROWAWAY keypair at power-on, discarded with the QR).** In Model B the game's signature proves only *structural* validity; provenance is meant to ride on operational control + a separate, out-of-scope companion app.
- **This ticket's question:** In pure-Nostr terms, how could a TRUSTED COMPANION (stable identity) vouch for / bind an event signed by an ephemeral game key? Survey NIP-26 (delegation), NIP-03 (OpenTimestamps), NIP-46/07 (remote signing), e/p/a tags, and attestation/badge patterns. What does a coherent Model-B wiring look like, and where does trust leak? Note NIP deprecation status.
- **Scope:** map the **landscape** (mechanisms × what each binds vs. does NOT) plus Ackoff reframings. PLANNING/SPEC work — **not** an implementation, **not** a go/no-go call.

> **Note on verification (per working discipline):** every claim below is tied to a named primary source (the NIP spec at github.com/nostr-protocol/nips, read firsthand this session). Where a fact is an inference from the specs rather than a direct quote, it is flagged inline. No inference is presented as a checked fact.

---

## 0. The invariant that dominates Model B

A Nostr event (NIP-01) is authenticated **solely** by a BIP-340 Schnorr signature over the event `id`, where `id = sha256([0, pubkey, created_at, kind, tags, content])`. Identity is "whoever holds the private key," full stop — the protocol has no notion of *who is allowed to hold* a key or whether an achievement is *true*.
- NIP-01: https://github.com/nostr-protocol/nips/blob/master/01.md (event fields `id, pubkey, created_at, kind, tags, content, sig`; id serialization; "Signatures … done according to the Schnorr signatures standard for the curve secp256k1", https://bips.xyz/340)

**Consequence for Model B:** an *ephemeral* game key is, cryptographically, indistinguishable from *any* freshly-generated key. A forger can mint their own ephemeral keypair off-console and hand-craft a structurally perfect, validly-signed "I got a star" event. So the ephemeral signature contributes **zero origin-provenance on its own** — exactly the premise of the ticket. Every mechanism surveyed below is therefore an attempt to move provenance **onto a separate, stable identity** and *bind* it to the ephemeral event. The question is always: **what does the stable identity actually verify before it vouches, and can that verification be forged?**

---

## 1. NIP-26 — Delegated event signing  ⚠️ UNRECOMMENDED

**Status:** the NIPs README explicitly marks NIP-26 **"unrecommended: adds unnecessary burden for little gain."**
- README status list: https://github.com/nostr-protocol/nips/blob/master/README.md
- NIP-26: https://github.com/nostr-protocol/nips/blob/master/26.md

**Mechanism.** A stable **delegator** authorizes a **delegatee** key to sign on its behalf. The delegator computes a *delegation token* = a Schnorr signature over `sha256("nostr:delegation:<delegatee_pubkey>:<conditions>")`. The delegatee then publishes normal events signed with *its own* key, adding a tag:
`["delegation", <delegator_pubkey>, <conditions_query_string>, <64-byte delegation token>]`.
Conditions are a `&`-joined query string over `kind` (`=`) and `created_at` (`<`,`>`), e.g. `kind=1&created_at>1674834236&created_at<1677426236`; the spec recommends always including a time window. Clients display the event as authored by the *delegator*; relays are expected to match the delegator's pubkey when the delegation tag is present. (NIP-26.)

**Fit to Model B.** This is the closest *literal* match to "companion vouches for game key": the companion (stable) is delegator, the ephemeral game key is delegatee. It would let the game's event be *attributed to* the companion's identity.

**Where it breaks / leaks trust:**
1. **Deprecated** — building a new feature on an unrecommended NIP means poor/declining client + relay support. (README.)
2. **The delegation token must be minted by the companion for that specific delegatee pubkey.** But the game mints its ephemeral key *at power-on, offline, per session*. To get a NIP-26 token the companion would have to sign the game's freshly-minted pubkey **at power-on** — i.e. the game needs a live round-trip to the companion *before* it can produce a delegated event. On an offline N64 emitting a static QR, that channel does not exist. *(Inference from NIP-26 token construction + platform constraints.)*
3. Even with the round-trip, the delegation token is a bearer credential: anyone who captures it (the token travels in the public event tag) can reuse it to sign *any* event matching the (coarse `kind`/`created_at`) conditions. Conditions cannot say "only for a real star from a real cartridge."

---

## 2. NIP-03 — OpenTimestamps attestations  ⚠️ UNRECOMMENDED

**Status:** README marks NIP-03 **"unrecommended: vulnerable to one specific attack, needs update."** The spec body itself carries the same "unrecommended" label.
- README: https://github.com/nostr-protocol/nips/blob/master/README.md
- NIP-03: https://github.com/nostr-protocol/nips/blob/master/03.md

**Mechanism.** A `kind:1040` event whose `content` is base64-encoded `.ots` (OpenTimestamps) proof data containing **a single Bitcoin attestation** (pending attestations excluded). It carries an `["e", <event-id>, <relay>]` tag and a `["k", <kind>]` tag. "The OpenTimestamps proof MUST prove the referenced `e` event id as its digest." (NIP-03.)

**What it proves / does NOT prove.** It anchors *existence-before-a-time* of the referenced event id to the Bitcoin blockchain. It says nothing about **who** produced the event or whether the achievement is real — only that the bytes existed by block time T. For Model B it can prove "this star event is not backdated / was minted before time T," which is a *freshness/ordering* property, not origin-provenance. Also unrecommended, and requires a Bitcoin/OTS calendar round-trip that the N64 cannot do; a companion would have to timestamp on the game's behalf.

---

## 3. NIP-46 (remote signing) & NIP-07 (window.nostr) — signer abstraction

**Status:** NIP-46 **active**; NIP-07 **active**.
- NIP-46: https://github.com/nostr-protocol/nips/blob/master/46.md
- NIP-07: https://github.com/nostr-protocol/nips/blob/master/07.md

**NIP-46 mechanism.** "Private keys should be exposed to as few systems … as possible." A **remote-signer ("bunker")** holds the real **user-keypair**; a **client** (which mints a *disposable* client-keypair per session) sends signing requests. RPCs (notably `sign_event`, which takes an unsigned event and returns `json_stringified(<signed_event>)`) travel as **`kind:24133`** events encrypted with NIP-44. Connection via **`bunker://<remote-signer-pubkey>?relay=…&secret=…`** (signer-initiated) or **`nostrconnect://<client-pubkey>?relay=…&secret=…&perms=…`** (client-initiated). (NIP-46.)

**NIP-07 mechanism.** Browser `window.nostr` exposing `getPublicKey()` and `signEvent(event)` (returns the event with `id/pubkey/sig`), so a web app never touches the key — signing is delegated to a trusted extension. (NIP-07.)

**Fit to Model B — this is the *dissolving* option, not a vouching option.** Both NIPs solve "the app should not hold the signing key" by having a **separate trusted signer produce the signature with a STABLE key.** If the game (client) delegated signing to the companion (signer), the resulting event's `pubkey` would be the **companion's stable identity — there would be no ephemeral game key at all, and origin-provenance would be native** (same effect as Model A but with the key living in the companion, not the ROM). Note NIP-46's disposable *client* key is only for the encrypted transport channel; the *authored* event carries the user/signer key. *(Inference from NIP-46 three-keypair model.)*

**Where it breaks on this platform.** NIP-46 requires a live, bidirectional, NIP-44-encrypted relay round-trip *at signing time*. An offline N64 emitting a one-way QR cannot participate. So NIP-46/07 describe the *correct* trust architecture but are **infeasible in-console**; they are only realizable if a companion device does the signing — which is Model A relocated to the companion.

---

## 4. Event references (e / p / a tags) — the primitive under every attestation

**Status:** core, **active** (NIP-01).
- NIP-01 tags: https://github.com/nostr-protocol/nips/blob/master/01.md

Standard references (NIP-01):
- `["e", <32-byte hex event id>, <relay url?>, <author pubkey?>]` — point at another event.
- `["p", <32-byte hex pubkey>, <relay url?>]` — point at a pubkey.
- `["a", "<kind>:<pubkey>:<d-tag>", <relay url?>]` — point at an addressable/replaceable event coordinate.

**Fit to Model B.** These are the raw material for "companion publishes a *second* event that references the game event." The companion emits an event with an `e` tag → the ephemeral game event id and a `p` tag → the ephemeral game pubkey, signed by the **companion's stable key**. That binds "companion asserts something about this specific ephemeral event" in a publicly verifiable, permanent way. Every higher-level attestation pattern (§5) is a *conventionalized* version of exactly this.

---

## 5. Attestation / vouching patterns (badges, reposts, DNS, relay auth)

| NIP | Status | Mechanism (primary source) | What it binds |
|---|---|---|---|
| **NIP-58 Badges** | active | Issuer publishes Badge Definition `kind:30009` (addressable, `d` tag), then Badge Award `kind:8` with an `a` tag → the definition and one or more `p` tags → recipients; recipient opts in via Profile Badges `kind:10008`. https://github.com/nostr-protocol/nips/blob/master/58.md | A **stable issuer** attests a claim about a recipient pubkey. Closest Nostr-native "attestation" primitive. |
| **NIP-18 Reposts / quotes** | active | `kind:6` (repost of kind 1), `kind:16` (generic repost, with `k` tag), quote via `["q", <event-id>, <relay>, <pubkey>]`. https://github.com/nostr-protocol/nips/blob/master/18.md | One pubkey **endorses/points at** another's event. Lightweight vouch. |
| **NIP-05 DNS identifier** | active | `/.well-known/nostr.json?name=<x>` maps a name@domain to a pubkey; MUST NOT follow redirects. https://github.com/nostr-protocol/nips/blob/master/05.md | Binds a pubkey to a **domain**. Spec: "not intended to *verify* a user, but only to *identify* them" — except as "an attestation of their relationship" with a well-known domain. |
| **NIP-42 relay auth** | active | Relay sends `["AUTH", <challenge>]`; client returns a signed `kind:22242` ephemeral event carrying `["relay", …]` and `["challenge", …]` tags. https://github.com/nostr-protocol/nips/blob/master/42.md | Proves **live control of a key** to a relay (operational-control signal), not published provenance. |

**Coherent Model-B wiring in pure Nostr (synthesis).** The load-bearing pattern is §4 + §5:
1. Game (ephemeral key K_e) mints the star event E, renders QR. E is structurally valid, provenance-empty.
2. Companion (stable identity K_c) ingests E (scans the QR / receives it), decides to vouch, and publishes an **attesting event** A signed by K_c: either a bare `e`/`p`-tag reference to E, a NIP-18 quote, or a **NIP-58 Badge Award (`kind:8`)** naming K_e via a `p` tag. Optionally A is anchored in time by NIP-03.
3. Verifiers trust E **only transitively through K_c's reputation**: "K_c, a known identity, attests this ephemeral star is legit."

This is coherent and uses only active NIPs (58/18/01) — but see §6 for exactly where the trust leaks.

---

## 6. Where trust leaks (the honest failure map)

**The central leak: the companion can only vouch for what it can independently verify — and the ephemeral signature gives it nothing to verify against.**

- The ephemeral signature proves *only* "some key signed these bytes" (§0). When the companion scans E, it sees a valid signature by an unknown, single-use key. **Nothing in E distinguishes a real cartridge from a forger who generated their own ephemeral key and typed a fake star event.** So K_c's attestation adds *K_c's reputation* to E, but **imports no new origin-provenance** unless K_c has a *separate, out-of-band* way to confirm the achievement was real (e.g. it watched the play session, or the game shares a real secret with it — which collapses back toward Model A). This is the ticket's core finding: **Nostr attestation relocates trust to the companion; it does not manufacture provenance the companion didn't already possess.**
- **Bearer-credential / replay leaks.** NIP-26 delegation tokens (§1) are public bearer tokens scoped only by `kind`/`created_at`; anyone who captures one can sign matching events. NIP-46 `secret`s and relay round-trips assume connectivity the N64 lacks (§3).
- **Deprecation leaks.** The two NIPs that map most literally to "delegate/attest" — NIP-26 and NIP-03 — are both **unrecommended** in the README, meaning eroding client/relay support and (for NIP-03) a known unpatched attack.
- **Platform leak.** Every mechanism that would let the *companion sign or co-sign at mint time* (NIP-26 token issuance, NIP-46 remote signing, NIP-03 calendar) needs a **live round-trip** the offline, one-way-QR N64 cannot make. The only mechanisms the console can support unaided are the *purely after-the-fact* ones (companion publishes an independent `e`/`p`/badge event *about* an already-emitted QR) — and those are exactly the ones that add no provenance (first bullet).
- **NIP-05 is not verification.** By its own words it identifies, not verifies (§5) — it cannot underwrite an achievement claim.

---

## 7. Ackoff SOLVE / RESOLVE / DISSOLVE

Russell Ackoff, *The Art of Problem Solving* (1978): **dissolve** = redesign the system so the problem cannot arise.

- **SOLVE (make the ephemeral event carry provenance via Nostr-native vouching):** NIP-58 Badge Award / NIP-18 quote / `e`+`p` reference from the stable companion, optionally NIP-03-timestamped. *Verdict:* works mechanically and uses active NIPs, but per §6 it only lends the companion's reputation — it does **not** let the companion verify a bare ephemeral event it didn't independently witness. NIP-26 is the literal fit but is **deprecated** and needs a mint-time round-trip the console can't do.
- **RESOLVE (accept it and contain blast radius):** treat the ephemeral signature as *structural validity only*, and make the **companion's out-of-band verification the actual provenance authority** — the companion publishes a NIP-58 badge / attestation only after confirming the play by an independent channel it controls. Provenance = "trust the companion," honestly labeled. This matches the ticket's own Model-B framing ("provenance rides on operational control + companion app").
- **DISSOLVE (remove the ephemeral key from the provenance path entirely):** the strong move, and the two active NIPs point straight at it. **NIP-46/07's entire thesis** is "the thing that authors the event should not be the thing that runs untrusted client code." If signing is done by the **companion's stable key** (game just presents a witness of the achievement; companion signs the real Nostr event), there is **no ephemeral game key in the provenance path**, and origin-provenance is native — the *same* end state as Model A, but with the secret living in an operator-controlled companion instead of a distributed ROM. The ephemeral-key-provenance problem is *dissolved*, not solved. (NIP-46, NIP-07.)

**Bridge to issue #8's conclusion.** The sibling anti-extraction research (`docs/research/key-anti-extraction.md`) concluded a client-held secret in a public ROM cannot be kept secret and the real fix is to move trust off the client key (server-held key + unforgeable client witness). This ticket reaches the *same terminus from the Nostr side*: no Nostr NIP lets an ephemeral, console-minted key acquire origin-provenance by itself; provenance must be anchored in a stable identity whose vouch is only as strong as its *independent* verification of the achievement. Model B is viable **only** if that companion-side verification exists and is trusted — the ephemeral signature never carries provenance on its own.

---

## 8. Honest bottom line

1. **No Nostr NIP manufactures origin-provenance for a self-minted ephemeral key.** A Nostr event is authenticated only by a signature over its id (NIP-01); an ephemeral game key is indistinguishable from a forger's freshly-minted key. §0.
2. **The literal "delegation" NIP (NIP-26) is unrecommended** ("adds unnecessary burden for little gain") **and** would need a mint-time round-trip the offline QR-emitting N64 cannot make. §1.
3. **NIP-03 timestamping is also unrecommended** and only proves existence-before-time, not origin. §2.
4. **NIP-46/07 describe the correct architecture (stable signer, disposable client)** — but they *dissolve* the ephemeral key rather than vouch for it, and require connectivity the console lacks; realizing them means the companion signs, i.e. Model A relocated. §3, §7.
5. **Active, feasible-after-the-fact vouching does exist** — a stable companion publishing a NIP-58 Badge Award / NIP-18 quote / `e`+`p` reference to the game event (§4–§5). **But it only lends the companion's reputation; it imports no provenance the companion didn't already verify out-of-band.** §6.
6. **Therefore Model B is viable *iff* the companion has an independent, trusted way to verify each achievement before it attests.** In pure Nostr terms, "the companion signs/attests" *is* the provenance; the ephemeral game signature is structural-validity plumbing only. This matches Model B's stated premise and converges with issue #8's "move trust off the client key" conclusion. §7.

*This document maps the landscape only. It is not an implementation and not a go/no-go recommendation.*
