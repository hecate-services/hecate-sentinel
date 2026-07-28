# DESIGN: The Enriched Fact Contract

**Status:** DRAFT — awaiting sign-off. Nothing here is implemented.
**Created:** 2026-07-28
**Last Updated:** 2026-07-28 (rev 2, after adversarial review)

## The decision this records

> "Sentinel just should do just 3 things: 1. subscribe to warden facts,
> 2. enrich as much as possible and 3. emit the enriched facts to the mesh.
> This way, other consumers can build their own specific read models for their
> own specific use cases."

That instruction is a given. This document translates it into a contract and
establishes what it costs. Anything not settled is parked in §11 rather than
decided here.

## 0. What changed in rev 2

Adversarial review refuted four claims in rev 1. They are corrected in place;
listed here so the corrections are not silently absorbed.

| rev 1 claimed | actually |
|---|---|
| A dropped message corrupts every subsequent delta under the cumulative contract | **Backwards.** The cumulative contract is drop-TOLERANT and self-healing. The proposed contract is the fragile one. See §2 and §4.3. |
| A deterministic id makes the event log idempotent | Not on its own. `threat_aggregate:execute/2` ignores state and emits unconditionally; a guard is also required. |
| Deleting `sentinel/attack` makes `Demos.Vigil` simpler | It sheds delta arithmetic and gains aggregation, dedup, and either a store or permanent amnesia. Net more code. See §6. |
| `sentinel/ensnare` can be emitted from the described pipeline | It cannot. The reporting box and timestamp are discarded before that point. Defect #5 is a prerequisite, not a deferrable. |

## 1. What is true today (verified against the code)

**The pipeline.** Wardens publish `warden/threats`, `warden/ensnared`,
`warden/presence`. `ingest_warden_reports` subscribes to the first two. A
sighting is dispatched as a `report_threat_v1` command and recorded as a
`threat_sighted_v1` event in the sentinel's reckon-db store. The projection
`threat_sighted_v1_to_threats` folds it into an ETS read model keyed by source
IP, and publishes to the mesh.

**Enrichment exists and is published.** `attack_fact/1`
(`record_threat/threat_sighted_v1_to_threats.erl:75`) carries `country_iso`,
`country`, `city`, `lat_e6`, `lng_e6`, `asn`, `asn_org`, `net_type`. Enrichment
runs once per IP on first sight, in `existing/1`
(`hecate_sentinel_threats.erl:113-121`, calling `safe_enrich/1` defined at
`:124`). It lives in the read model and is never written to the event.

**Cadence is one message per sighting.** `record/3:43` calls `announce/2` at
`:47`; `emit/2:61` publishes `?ATTACK_TOPIC` at `:62`. `?CAMPAIGN_TOPIC` is
published only on the cross-border transition (`emit_crossed/2:67`).

**Payload grain is cumulative per IP.** `attack_fact/1` reads the accumulated
row: `total_attempts` is a running total, `usernames` an accumulated set, and
`boxes` is `maps:keys(wardens)` — every box that has *ever* seen that IP, not
the box that reported this sighting.

**Measured state (2026-07-28):** 16665 events replayed at sentinel boot on
2026-07-26 (container log); 1573 IPs in the live model. No per-day rate has been
measured and none is assumed here.

### 1.1 Fields, and where each one dies

| field | warden publishes | in `threat_sighted_v1` | in ETS row | in `sentinel/attack` |
|---|---|---|---|---|
| `source_ip` | yes | yes | yes | yes (`ip`) |
| `label` (reporting box) | yes | yes | yes | **no** (only accumulated `boxes`) |
| `attempts` | yes | yes | accumulated | accumulated |
| `usernames` | yes | yes | accumulated | accumulated |
| `service` | yes | yes | yes | hardcoded `<<"ssh">>` (`:88`) |
| `window_s` | yes (`sense_auth_log.erl:227`) | yes (`ingest:94`) | **no** (`row/1:92` drops it) | no |
| `tenant_id` | yes (`hecate_warden_facts.erl:23`) | **no** (never dispatched) | no | no |
| `reporter` (service DID) | yes (`:122-127`) | yes | yes | **no** |
| `at` | yes | yes | yes | re-stamped `system_time` (`:93`) |
| geo / ASN / net_type | n/a | never evented | yes | yes |

**Ensnares are a thinner path.** `on_ensnared/1:102` calls `ensnare/2:107`,
which passes **only `(Ip, HeldMs)`** to `record_ensnared/2`. The reporting box,
the timestamp and the tenant are discarded there. Ensnares are never recorded as
domain events — `ingest_warden_reports`' moduledoc states this is deliberate
("lower stakes, no evidence needed"). `held_ms` exists only in volatile ETS.

### 1.2 Consumers today

- `Demos.Threats` — `warden/threats` + `warden/ensnared` (`threats.ex:29`): the
  **raw** warden stream.
- `Demos.Vigil` — `sentinel/attack` + `sentinel/campaign` + `warden/presence`
  (`vigil.ex:43`): the enriched stream.

## 2. The defect, stated correctly

The contract took the shape of one consumer's read model. Its own commit says so
(`6dc1397`, 2026-07-14): "observers upsert by IP so a boot-replay burst just
re-paints".

Upsert-by-IP is right for a map. As the *public contract* it has two measured
consequences:

1. **Sightings cannot be attributed.** `boxes` is a union over all time, so no
   consumer can answer "which box saw this IP, when". Every per-box or
   time-bucketed view is impossible from the published contract. **This is the
   whole case for changing it.**
2. **Other use cases are locked out**, the immediate one being an inspection
   view over attacks and campaigns.

**What is NOT wrong with it, contrary to rev 1.** The cumulative contract is
drop-tolerant. `vigil.ex:125-133` computes `delta = max(attempts - previous, 0)`
against the last *received* total, so a dropped snapshot costs nothing and the
next one absorbs the gap. It self-heals under mesh loss and across consumer
restarts. **The proposed contract gives that up**, which §4.3 must answer.

## 3. Proposed contract (PROPOSAL — not agreed)

One enriched fact out per warden fact in.

**`sentinel/sighting`**

```
type            sentinel_sighting
sighting_id     deterministic (see §4)
seq             per-sentinel monotonic, so consumers can DETECT gaps (§4.3)
ip              source IP
box             the REPORTING box, for this sighting
reporter        the warden's service DID (provenance)
tenant_id       operator attribution
service, attempts, window_s, usernames   as reported, NOT accumulated
at              the WARDEN's timestamp, not re-stamped
country_iso, country, city, lat_e6, lng_e6, asn, asn_org, net_type
```

**`sentinel/ensnare`** — same identity/enrichment fields, plus `held_ms`.
Requires defect #5 fixed first (§9).

`tenant_id` and `reporter` are included because rev 1 called dropping them a
defect and then omitted them; a contract that ships without them needs a v2
within the month.

**Wire cost is neutral for sightings.** One `sentinel/attack` is published per
sighting today; one `sentinel/sighting` would be. Payload is comparable or
smaller (this sighting's usernames, not the accumulated set).
`sentinel/ensnare` is genuinely new traffic.

## 4. Identity, replay, and loss

### 4.1 Deterministic id

Today `dispatch_sighting/2:86` mints `sighting_id` from
`crypto:strong_rand_bytes(16)` **per mesh delivery**, so a redelivery becomes a
distinct event. Proposed: derive it from the fact.

The key must cover every discriminating field, so `(source_ip, label, service,
at)` — **not** `(source_ip, label, at)` as rev 1 had it. Two sensors on one
warden firing off the same tick can produce the same ip/label/millisecond for
different services, and the narrower key silently loses one.

`at` is stamped exactly once, at publish (`hecate_warden_facts.erl:129-130`);
the warden's sighting map carries none (`sense_auth_log.erl:224-228`). So the
same observation carries the same `at` through redelivery and store replay,
which is what makes the key stable. A warden restart reopens the tail at EOF
(`sense_auth_log.erl:115-116`), so post-restart reports are genuinely new
observations and deserve new ids.

**Unresolved:** `label()` returns `undefined` when unset
(`hecate_warden_facts.erl:104-108`), and the ETS path falls back to the
ephemeral reporter DID (`warden_key/2`, `hecate_sentinel_threats.erl:152-153`).
The key must either adopt `warden_key` semantics or reject unlabeled reports.

**A deterministic id alone does not make the log idempotent.**
`threat_aggregate:execute/2` ignores state and emits unconditionally, so a
redelivery appends a second identical event to the same stream. A guard clause
in `execute` is required alongside.

### 4.2 Live versus replay

Rev 1 proposed "publish on live ingest only". **The code as built forbids it
where emission currently lives.** The projection's checkpoint read model is
`evoq_read_model_ets` (`threat_sighted_v1_to_threats.erl:22,32`), which is
volatile, so every boot replays from zero with nothing marking events as
historical. The `:74` comment confirms today's boot behaviour is a full
re-publish burst.

**Consequence: emission must move to `ingest_warden_reports`.** That is the only
point that is live by construction, and independently the only point where the
ensnare's box and timestamp still exist (§1.1). Two separate findings force the
same relocation.

Open: whether a fact may be emitted when the evidence dispatch failed.

### 4.3 The loss problem this creates, and the gap in rev 1

Rev 1 said never re-emit on catch-up (§4) while also claiming the evidence chain
"is what makes re-emission and backfill possible" (§7). Those contradict.

On an at-most-once mesh, a fact-grain contract with no reconciliation means a
dropped fact is lost to that consumer **permanently and undetectably**, and a
consumer that loses its store can never acquire history. The cumulative contract
had this covered by accident. Any honest version of this design needs one of:

- **a low-cadence per-IP checkpoint summary fact** that consumers reconcile
  against — a demoted `sentinel/attack`, which is ironic and may still be right;
- **an operator-triggered backfill** re-emitting from the evidence chain, leaning
  on §4.1 idempotency;
- at minimum, the **`seq` field** in §3 so consumers can detect the gaps they
  cannot recover.

**Not decided here.** This is the single most important open question in the
document.

## 5. Enrichment quality

`safe_enrich/1` caches `#{}` permanently on first failure
(`hecate_sentinel_threats.erl:121-125`). An IP first seen during a geo-DB outage
emits unenriched facts for its whole life. Pre-existing, but "enrich as much as
possible" should commit to retry-on-empty.

## 6. What this costs `Demos.Vigil`

Rev 1 claimed it gets simpler. Corrected: it sheds the delta arithmetic
(`vigil.ex:119-133`) and gains three things.

1. **Aggregation it currently receives pre-joined.** `boxes`, the usernames
   union and cumulative attempts arrive computed today (`attack_fact/1:87-90`).
   Folding sightings, Vigil reimplements a slice of
   `hecate_sentinel_threats:merge/2` in Elixir, and `became_wide` too if
   campaigns become a consumer concern.
2. **Dedup.** Additive folding double-counts on redelivery, so Vigil needs a
   seen-id set per *sighting*, roughly 10x the tally's cardinality (16665 events
   against 1573 IPs), with time-windowed eviction. More code than the delta it
   replaces.
3. **Persistence, or accepted amnesia.** Today a realm restart self-heals: the
   next cumulative snapshot carries full history. Under fact grain it does not.
   The map zeroes on every redeploy.

The tally and `tally_capped` (`vigil.ex:34-38`) are **not** purely
contract-induced, contrary to rev 1: they also provide `attacker_count` beyond
the 400-row render window. A bounded per-IP set is still needed.

### 6.1 This collides with an existing, reviewed decision

`macula-realm/plans/DESIGN_LEDGER_VISUALISATION.md` §4 (lines 257-275) hit the
identical problem for `/ledger` and resolved it the other way:

> either the realm gains a store for this view (breaking §0 property 1, which
> this document declared load-bearing) or it ships an amnesiac ledger
> (destroying the thesis). **Resolution: neither. Move the history out of the
> realm.** ... The realm stays amnesiac and honest; the memory lives where
> memory belongs.

The owner's instruction for the inspection view is the opposite: the realm
maintains an embedded store fed by projecting mesh facts. Both positions are
defensible and the cases differ, but **the conflict must be resolved knowingly,
not by whichever document is read last.** That doc also declares (§0, lines
52-57) that the realm renders an explicit public contract and never raw warden
facts — a rule `sentinel/sighting` satisfies and which rules out any design that
has the realm project `warden/threats` directly.

## 7. What is not enrichment

`sentinel/campaign` is a correlation: same IP, two or more boxes. Under the
three-responsibilities rule any consumer can compute it.

But alerting the minds on the cross-border **transition** is stateful, and a
pure enricher cannot detect a transition. So either the sentinel keeps a read
model, in which case it is not a pure enricher and §8 is wrong, or a new slice
owns that state, in which case it inherits a re-detection problem: a correlator
that loses its state re-detects every historical crossing and re-broadcasts,
backstopped only by the constant `msg_id` `threat-<ip>`
(`threat_sighted_v1_to_threats.erl:143`) — itself a quirk, since a genuinely
returning campaign can never re-alert.

`broadcast_digest` has the same dependency: `maybe_publish` reads
`hecate_sentinel_threats:all()` (`broadcast_threat_digest.erl:55`).

**Rev 1 deferred this. The review is right that it cannot be deferred:** whether
the sentinel keeps a read model at all determines §8, the defect ordering in §9,
and the topic list in §3. The document is not signable while it is open.

## 8. What stays

The reckon-db evidence chain: the material an abuse report is built from, held
off the attacked box, and the only possible source for any backfill under §4.3.
Subject to §7.

## 9. Pre-existing defects, reclassified

Rev 1 asked whether to fix these before or after. That was a false choice: three
of them *are* the contract work.

| # | defect | status |
|---|---|---|
| 2 | random `sighting_id` (`ingest:86`) | **is the design** (§4.1), not a separate item |
| 3 | double-fold on restart: `rebuild/0` (`hecate_sentinel_threats.erl:84-87`) and the projection's `record/3` both fold into the same ETS | **near-confirmed and constitutive.** Also propagates today: an inflated post-restart total produces an inflated delta in Vigil |
| 5 | ensnares lose box and timestamp (`ensnare/2:107`) | **hard prerequisite** for the ensnare topic |
| 1 | `read_all/1` caps at 50000 (`:167-169`), no truncation log | deferrable at current volume **if** a warning is added; fatal to §4.3 backfill; can cause a false `crossed_border` and a spurious minds alert after a partial rebuild |
| 4 | `tenant_id` dropped at ingest | not a defect to sequence — belongs in §3 |

Bonus, found in review: `hecate_sentinel_threats.erl:64-65` logs
`length(Events)` as "~b IPs". That log line reports events and calls them IPs,
which is why the boot log said 16665 while the model held 1573.

## 10. Sequencing — no flag day

"Deleted, not deprecated" is code hygiene, not a deployment order. Dual
publishing during the transition is the migration, not backward compatibility.

1. **Deterministic id + aggregate guard.** Sentinel-only, invisible to
   consumers, stops log inflation from redelivery immediately, and everything
   else leans on it. Smallest safe first move.
2. **Emit `sentinel/sighting` and `sentinel/ensnare` from
   `ingest_warden_reports`**, alongside the existing topics. Additive; settles
   live-vs-replay by construction (§4.2).
3. **Realm grows the sighting-fold path** while `/vigil` still runs on the old
   topics. Running both in parallel is also the cheap test for defect #3.
4. **Delete `sentinel/attack` and the Vigil delta code** once parity holds. Then
   settle `Demos.Threats` and the campaign/alerting slice.

## 11. Open questions — require sign-off before any code

1. **§4.3: which reconciliation mechanism** — checkpoint summary fact, operator
   backfill, or `seq`-for-detection only? Without one, this contract is worse on
   a lossy mesh than what it replaces.
2. **§7: does the sentinel keep a read model?** Everything else hangs from this.
3. **§6.1: realm store, or the `/ledger` doc's "move history to the producer"?**
   Two of your own designs currently disagree.
4. Topic names: `sentinel/sighting`, `sentinel/ensnare`?
5. Is `(source_ip, label, service, at)` the natural key, and what happens to
   unlabeled wardens (§4.1)?
6. Does `sentinel/campaign` survive as a published fact?
7. May a fact be emitted when the evidence dispatch failed (§4.2)?
8. Is the enrichment remit the current set, plus retry-on-empty (§5)? Or also
   reverse DNS, first-seen-ever, known-scanner ranges?
9. Does `Demos.Threats` keep consuming raw warden facts, given the `/ledger`
   doc's rule against it?
10. Fix defect #1's missing truncation warning now, or accept it?

## 12. Known downstream breakage

- `macula-realm/plans/DESIGN_LEDGER_VISUALISATION.md` is written against
  `sentinel/attack` and `sentinel/campaign` (lines 55, 194, 337). Partly
  superseded by this; needs reconciling, not silently invalidating.
- `macula-realm/system/scripts/check_vigil_counting.exs` encodes the delta
  contract and dies with the rewrite.
- **Ensnares would gain a public contract while still having no durable record
  anywhere** — not evented by deliberate decision, ETS-only. Publishing
  `sentinel/ensnare` makes "lower stakes, no evidence needed" false. That
  decision needs re-justifying or reversing.
- hecate-spartan: clean. No `sentinel/*` consumption; its interface is
  `spartan/broadcast`, which moves only if §7's slice moves.

## 13. Not in scope

Implementation. Nothing here has been built.
