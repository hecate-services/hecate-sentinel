# Changelog

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
