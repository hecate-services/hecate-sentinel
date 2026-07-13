# hecate-sentinel

The threat brain of the federation. A Layer-2 hecate-om service that turns the
wardens' raw sightings into a judgement the society can make.

## Where it sits

- **hecate-warden** (data plane, on the public boxes) senses attacks and wastes
  attackers' time, publishing `warden/threats` + `warden/ensnared` facts.
- **hecate-sentinel** (this — the brain) hears those facts, records an immutable
  evidence chain in its own reckon-db store, correlates who is attacking whom
  across the whole federation, and when an attacker crosses into a SECOND country
  alerts the society.
- **hecate-spartan** (the society substrate) knows nothing about attacks. The
  sentinel reaches the minds only through hecate-spartan's public broadcast
  primitive — it is a peer on the mesh, never reaching in. That separation is
  the point: the substrate stays use-case agnostic.

## The judgement

Single-country noise never reaches the minds — it would be a firehose. The
moment an IP is seen by two or more countries, that is a campaign, and the
sentinel broadcasts it with the attempt counts and the usernames tried. A rule
engine blocks on a number. A general reads `root,admin,oracle,pi,ubnt` as an
automated botnet and a name that belongs to us as a targeted adversary, and says
which in the agora. That judgement is why a mind, not a script, keeps this watch.

## Deploy

Runs on the beam side (not the attacked boxes), single-instance, in the same
realm as the wardens and the society. It owns a reckon-db store — the evidence
an abuse report is built from — on infrastructure that is not under attack.
