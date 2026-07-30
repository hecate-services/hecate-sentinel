# hecate-sentinel

> **Status: live and maintained.** Running on beam02 (as a Docker container under
> the `hecate-reconcile` timer, not a podman quadlet, so check `docker ps` and not
> `systemctl --user`), feeding the public threat map at
> [macula.io/vigil](https://macula.io/vigil).
>
> **One thing changed in the reinstatement, and the rest of this README depends
> on it: the minds are gone.** The hecate-spartan society was decommissioned
> 2026-07-19 when its memory thesis was falsified, so nothing consumes
> `spartan/broadcast` today. That publish path is still wired and still fires
> (see `broadcast_digest/`); it is landing in an empty room. The live consumer is
> the map.
>
> History, so the commit log reads straight: deprecated 2026-07-18 in a pivot
> away from the cybersecurity use case, reinstated 2026-07-23.

The threat brain of the federation. A Layer-2 hecate-om service that turns the
wardens' raw sightings into a correlated, provenanced threat picture.

## Where it sits

- **hecate-warden** (data plane, on the public boxes) senses attacks and wastes
  attackers' time, publishing `warden/threats` + `warden/ensnared` facts.
- **hecate-sentinel** (this — the brain) hears those facts, records an immutable
  evidence chain in its own reckon-db store, correlates who is attacking whom
  across the whole federation, and marks an attacker that crosses into a SECOND
  country as a campaign.
- **macula.io/vigil** (the public map) folds `sentinel/sighting` into the live
  view. macula-realm keeps its own CubDB archive plus a gap ledger, so the map
  holds history without depending on this service staying up.
- **hecate-spartan** (the former society substrate) knew nothing about attacks.
  The sentinel reached the minds only by publishing a `spartan/broadcast` fact as
  a peer on the mesh, never reaching in. That separation held, and it is why
  decommissioning the minds cost this service nothing structural: one publish
  call now has no subscriber.

## The threshold

Single-country noise is a firehose, so it lands on the map and escalates no
further. The moment an IP is seen by two or more countries, that is a campaign,
and the sentinel says so with the attempt counts and the usernames tried.

That threshold is the whole design. A blocklist fires on a number, while a
campaign is a claim about intent: `root,admin,oracle,pi,ubnt` reads as an
automated botnet, and a username that belongs to us reads as a targeted
adversary. The sentinel draws the line and publishes both sides of it. Deciding
which of the two you are looking at was the minds' job, and is currently nobody's
(see the status note above).

## What it publishes

Two contracts run in parallel on purpose, pending a parity check before the older
one is retired. See `plans/DESIGN_ENRICHED_FACT_CONTRACT.md`.

| Topic | Contract | Grain |
|---|---|---|
| `sentinel/sighting` | current | one observation, emitted from ingest |
| `sentinel/ensnare` | current | one tarpit ensnarement |
| `sentinel/heartbeat` | current | liveness, so silence is distinguishable from calm |
| `sentinel/attack` | older | cumulative per-IP state, emitted from the projection |
| `sentinel/campaign` | older | cross-border escalation |
| `spartan/broadcast` | orphaned | no subscriber since 2026-07-19 |

## Deploy

Runs on the beam side (not the attacked boxes), single-instance, in the same
realm as the wardens. It owns a reckon-db store — the evidence an abuse report is
built from — on infrastructure that is not under attack. The store rebuilds its
read model from that log at boot.
