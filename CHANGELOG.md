# Changelog

## [0.1.4]

### Fixed
- `reckon_db` 5.11.1 -> 5.11.4: `read_all_global/3`'s catch-up cache
  redesigned from one big list to one ETS row per event with generation
  tagging (67x on real 87k-event data, 11.0s -> 164ms). This is what let
  this service run at all -- 5.11.1's version of the same fix left the
  catch-up path too slow to finish before evoq's subscriber gave up,
  which is why this service was undeployed since 2026-09-01.
- `evoq` 1.23.1 -> 1.23.3: `evoq_store_subscription` acked catch-up
  progress AFTER subscribing to `$all` instead of before, leaving a gap
  where a reconnect mid-catch-up replayed already-delivered events to
  every projection and process manager on every boot since 2026-03-19.
  Fixed by acking before subscribing and coalescing acks. Only halves
  hecate-sentinel's own symptom on its own (see next item).
- `reckon_gater` 3.11.0 -> 3.11.2: stopped the `prod` profile from
  stripping consumers' debug_info.
- New `sentinel_alert_dedup` (this service): `threat_sighted_v1_to_threats`
  replays its ENTIRE history on every boot by design (the read model,
  `hecate_sentinel_threats`, is ephemeral and meant to be rebuilt from the
  log) -- evoq's per-projection checkpoint isn't the right tool here,
  since gating the whole `project/4` call would silently stop
  repopulating history older than the checkpoint. Added a narrow,
  per-attacker-IP persistent marker instead, scoped specifically to the
  `spartan/broadcast` minds notification: a restart's replay re-detects
  the same historical border-crossing (it always will, that's the read
  model working as designed) without re-notifying anyone about it who
  was already told. `sentinel/campaign` and the read-model upsert are
  both left unconditional -- Vigil folds by IP, a boot-replay repaint is
  harmless. Closes the degraded case `hecate_sentinel_threats`'s own
  rebuild-failure comments already anticipated (a truncated or failed
  read-model rebuild would otherwise make the projection's own replay
  re-detect the crossing as new); an ordinary restart's read-model
  rebuild runs before the projection's own catch-up (supervisor child
  order) and generally isn't affected, but the marker is
  order-independent and costs nothing either way.

## [0.1.3]

### Changed
- Bumped `hecate_om` `~> 0.15` -> `~> 0.16` (was actually too tight to
  even resolve 0.16.x), now at 0.16.5, which picks up `reckon_db`
  5.11.1 -- the actual fix for the 115%+ CPU catch-up loop found
  deploying 0.1.2 to beam00 (`read_all_global/3` was re-scanning and
  re-sorting the entire event store on every paginated call; see
  reckon_db's own CHANGELOG for the full writeup). The move to beam00
  isolated the blast radius; this is the real fix.

## [0.1.2]

### Fixed

- `capabilities/0` returned plain binaries (`[<<"sentinel.correlate_threats">>,
  <<"sentinel.alert_society">>]`); `hecate_om_service:capability()` has
  been `#{name := binary(), version := pos_integer(), ...}` since at least
  hecate_om 0.16.4. Never caught because 0.1.1's `identity_key_path` fix
  was needed just to REACH the code path that cares about the shape --
  with no keypair, `build_advertisement/6` was never called at all. Same
  bug hecate-warden hit deploying its own 0.2.2, same session; found here
  by inspection before deploying rather than live in production.

## [0.1.1] - first tagged release

### Fixed
- `identity_key_path` was never set in `config/sys.config.src` -- without
  it, `hecate_om_identity:keypair/0` returns `{error, no_keypair}` forever
  and capability advertisement (`sentinel.correlate_threats`,
  `sentinel.alert_society`) silently no-ops on every republish tick. No
  crash, no error logged; the node just never actually reachable on the
  mesh. hecate_om >= 0.14.1 self-heals a missing/corrupt keypair FILE at a
  configured path, but this service never had a path configured at all, so
  the `~> 0.15` bump below did not fix it on its own. Same bug class
  hecate-mail, hecate-tube, hecate-rag, hecate-embedder and hecate-warden
  each independently hit -- confirmed via a live DHT sweep of all 7 fleet
  stations showing zero `sentinel.*` records anywhere. Reuses the existing
  `HECATE_DATA_DIR` (this service already owns a real reckon-db store)
  rather than introducing a second path.
- Bumped `hecate_om` dependency `~> 0.10` -> `~> 0.15` (resolves 0.15.1,
  transitively macula 10.0.0 -> 10.10.0). Had drifted well behind the
  fleet, including the domain-filter fix that was silently dropping
  every `macula_diagnostics:event/2,3` call on any consumer. Full
  eunit suite clean at the new versions.

### Added
- Initial hecate-sentinel, extracted from hecate-spartan so the society
  substrate stays use-case agnostic.
- `ingest_warden_reports`: subscribes `warden/threats` + `warden/ensnared`,
  records each sighting as a `threat_sighted_v1` domain event (the evidence
  chain, in its own store) and folds tarpit ensnarements into the read model.
- `hecate_sentinel_threats`: per-IP aggregation with cross-border detection.
- `threat_sighted_v1_to_threats`: on a cross-border transition, broadcasts a
  `[THREAT]` alert to the society via `spartan/broadcast` — never reaching into
  hecate-spartan.
- Elvis (org structural ruleset) + lint/test CI.
