%%% @doc Hecate Sentinel — implements the hecate_om_service behaviour.
%%%
%%% The threat brain of the federation. The wardens (data plane, on the public
%%% boxes) sense attacks and waste attackers' time; they publish `warden/threats'
%%% and `warden/ensnared' facts. This service hears them, records an immutable
%%% evidence chain (its OWN reckon-db store — the material an abuse report is
%%% built from), correlates who is attacking whom across the whole federation,
%%% and when an attacker crosses into a SECOND country it alerts the society.
%%%
%%% It alerts through hecate-spartan's PUBLIC broadcast primitive — it publishes
%%% a `spartan/broadcast' fact, which every hecate-spartan node delivers to its
%%% local minds. It never reaches into hecate-spartan. That separation is the
%%% point: the society substrate knows nothing about attacks; the cyber-defense
%%% use case lives entirely here.
-module(hecate_sentinel_service).
-behaviour(hecate_om_service).

-export([info/0, start/1, stop/1, health/0, capabilities/0, identity_spec/0]).
-export([store_id/0, data_dir/0, store_indexes/0]).

info() ->
    #{name        => <<"hecate-sentinel">>,
      version     => <<"0.1.0">>,
      description => <<"Threat brain: correlates warden reports, alerts the society">>}.

start(_Opts) ->
    hecate_sentinel_sup:start_link().

stop(_State) ->
    ok.

health() ->
    ok.

%% It consumes warden facts and produces alerts + evidence. Nothing it does
%% reaches toward an attacker.
capabilities() ->
    [<<"sentinel.correlate_threats">>, <<"sentinel.alert_society">>].

identity_spec() ->
    #{scope     => <<"sentinel">>,
      actions   => [<<"alert">>],
      resources => [<<"spartan/*">>],
      ttl_days  => 30}.

%% ---- store callbacks (the evidence chain) ----

store_id() ->
    {ok, Id} = application:get_env(hecate_sentinel, event_store_id),
    Id.

data_dir() ->
    {ok, Dir} = application:get_env(hecate_sentinel, data_dir),
    Dir.

%% Threat sightings are looked up by source IP; index the payload so an abuse
%% report can find every sighting for an attacker without a full scan.
store_indexes() ->
    [event_type, {payload, <<"source_ip">>}].
