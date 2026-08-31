# Changelog

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
