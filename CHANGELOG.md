# Changelog

## [Unreleased]

### Fixed
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
