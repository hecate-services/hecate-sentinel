%%% @doc Top supervisor for hecate_sentinel.
-module(hecate_sentinel_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_one, intensity => 5, period => 10},
    Children = [
        %% GeoIP + ASN enrichment. Loads the MaxMind databases (if mounted) and
        %% answers where an attacker is and what network it belongs to. Starts
        %% first: the read model enriches each attacker as it records it.
        worker(hecate_sentinel_enrich),

        %% The threat read model. Owns the `threats' ETS table (per-IP
        %% aggregation + cross-border detection); starts before the projection
        %% that writes it. Rebuilds from the evidence log at boot.
        worker(hecate_sentinel_threats),

        %% Projection: threat_sighted_v1 -> the read model, and — when an IP
        %% crosses into a second country — a broadcast alert to the society.
        projection(threat_sighted_v1_to_threats),

        %% The mesh consumer: hears warden facts and turns each sighting into a
        %% recorded threat_sighted_v1 (the evidence chain). Also folds tarpit
        %% ensnarements into the read model.
        worker(ingest_warden_reports),

        %% A paced heartbeat: broadcasts a THREAT DIGEST to the society on a
        %% timer, but only when the landscape has actually moved — so the minds
        %% get real deltas between cross-border crossings instead of silence.
        worker(broadcast_threat_digest)
    ],
    {ok, {SupFlags, Children}}.

projection(Module) ->
    #{id => Module,
      start => {evoq_projection, start_link,
                [Module, #{}, #{store_id => hecate_sentinel_store}]},
      restart => permanent, shutdown => 5000, type => worker,
      modules => [Module]}.

worker(Module) ->
    #{id => Module,
      start => {Module, start_link, []},
      restart => permanent, shutdown => 5000, type => worker,
      modules => [Module]}.
