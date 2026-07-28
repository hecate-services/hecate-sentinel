%%% @doc The sentinel's public contract: one enriched fact out per warden fact in.
%%%
%%% This is the whole job. A warden senses and reports; this enriches what it
%%% reported with where the attacker is and what network it belongs to, and puts
%%% it back on the mesh at the SAME grain it arrived. Consumers build whatever
%%% read model they need from that.
%%%
%%% The contract it replaces, `sentinel/attack', carried CUMULATIVE per-IP state
%%% because the map that consumed it wanted upsert-by-IP. That shape cannot say
%%% which box saw an attacker when — its `boxes' field is the union over all
%%% time — so every other consumer was locked out. See
%%% plans/DESIGN_ENRICHED_FACT_CONTRACT.md.
%%%
%%% Published from the INGEST path, not from the projection, for two independent
%%% reasons: ingest is live by construction (the projection replays its whole
%%% checkpoint on every boot, so it cannot tell a new sighting from a replayed
%%% one), and ingest is the only place an ensnare still has its box and
%%% timestamp.
-module(publish_enriched_fact).

-export([sighting/3, ensnare/3, heartbeat/1]).
%% Fact builders, separated from publication so the contract shape can be
%% pinned without a mesh. Exported for tests.
-export([sighting_fact/3, ensnare_fact/3, heartbeat_fact/1]).

-define(SIGHTING_TOPIC,  <<"sentinel/sighting">>).
-define(ENSNARE_TOPIC,   <<"sentinel/ensnare">>).
-define(HEARTBEAT_TOPIC, <<"sentinel/heartbeat">>).

%% @doc One observation, enriched. `Stamp' is `{Epoch, Seq}'.
-spec sighting(binary(), map(), {integer(), non_neg_integer()}) -> ok.
sighting(SightingId, F, Stamp) ->
    publish(?SIGHTING_TOPIC, sighting_fact(SightingId, F, Stamp)).

-spec sighting_fact(binary(), map(), {integer(), non_neg_integer()}) -> map().
sighting_fact(SightingId, F, {Epoch, Seq}) ->
    Ip = mget(source_ip, F),
    enrich(Ip,
                   #{type        => sentinel_sighting,
                     sighting_id => SightingId,
                     epoch       => Epoch,
                     seq         => Seq,
                     ip          => Ip,
                     box         => mget(label, F),
                     reporter    => mget(warden, F),
                     tenant_id   => mget(tenant_id, F),
                     service     => default(mget(service, F), <<"ssh">>),
                     attempts    => default(mget(attempts, F), 1),
                     window_s    => default(mget(window_s, F), 60),
                     usernames   => usernames(mget(usernames, F)),
                     at          => mget(at, F)}).

%% @doc One tarpit capture, enriched.
%%
%% Deliberately carries NO `seq'. The sequence numbers what is EVENTED, and an
%% ensnare is not: `ingest_warden_reports' folds it straight into the read model
%% because the evidence chain is built from sightings. So an ensnare lost on the
%% mesh is undetectable by a consumer, and saying otherwise with a number that
%% counts something else would be worse than the silence.
-spec ensnare(binary(), non_neg_integer(), map()) -> ok.
ensnare(Ip, HeldMs, F) ->
    publish(?ENSNARE_TOPIC, ensnare_fact(Ip, HeldMs, F)).

-spec ensnare_fact(binary(), non_neg_integer(), map()) -> map().
ensnare_fact(Ip, HeldMs, F) ->
    enrich(Ip,
                   #{type      => sentinel_ensnare,
                     ip        => Ip,
                     box       => mget(label, F),
                     reporter  => mget(warden, F),
                     tenant_id => mget(tenant_id, F),
                     held_ms   => HeldMs,
                     at        => mget(at, F)}).

%% @doc The beacon. Carries the current stamp and nothing else.
%%
%% `seq' alone can only reveal a gap when the NEXT fact arrives. The failure
%% this mesh has actually produced is indefinite silent deafness on a
%% connection, where no next fact ever arrives and a consumer renders "quiet"
%% exactly as it renders genuinely quiet. This recovers nothing and reconciles
%% nothing; it converts deaf into DETECTABLY deaf within one period.
-spec heartbeat({integer(), non_neg_integer()}) -> ok.
heartbeat(Stamp) ->
    publish(?HEARTBEAT_TOPIC, heartbeat_fact(Stamp)).

-spec heartbeat_fact({integer(), non_neg_integer()}) -> map().
heartbeat_fact({Epoch, Seq}) ->
    #{type  => sentinel_heartbeat,
      epoch => Epoch,
      seq   => Seq,
      at    => erlang:system_time(millisecond)}.

%% --- Internal ---

%% Where the attacker is and what network it belongs to. Looked up per fact
%% rather than read from the threat model, deliberately: the model caches an
%% empty result forever if the first lookup for an IP fails, so an IP first seen
%% during a geo-database outage would be unenriched for its whole life.
enrich(Ip, Fact) when is_binary(Ip) ->
    Geo = safe_lookup(Ip),
    prune(Fact#{country_iso => g(country_iso, Geo),
                country     => g(country, Geo),
                city        => g(city, Geo),
                lat_e6      => e6(g(lat, Geo)),
                lng_e6      => e6(g(lng, Geo)),
                asn         => g(asn, Geo),
                asn_org     => g(asn_org, Geo),
                net_type    => g(net_type, Geo)});
enrich(_Ip, Fact) ->
    prune(Fact).

safe_lookup(Ip) ->
    try hecate_sentinel_enrich:lookup(Ip) catch _:_ -> #{} end.

%% Coordinates travel as micro-degree INTEGERS, matching the contract this one
%% sits beside. macula 7.0 carries IEEE floats natively, so this could be
%% relaxed, but not silently and not in the same change.
e6(F) when is_float(F)   -> round(F * 1000000);
e6(N) when is_integer(N) -> N * 1000000;
e6(_)                    -> undefined.

usernames(L) when is_list(L) -> lists:sublist([U || U <- L, is_binary(U)], 20);
usernames(_)                 -> [].

g(K, M) when is_map(M) -> maps:get(K, M, undefined);
g(_K, _M)              -> undefined.

prune(M) -> maps:filter(fun(_K, V) -> V =/= undefined end, M).

default(undefined, Def) -> Def;
default(V, _Def)        -> V.

mget(K, M) -> maps:get(K, M, maps:get(atom_to_binary(K, utf8), M, undefined)).

publish(Topic, Fact) ->
    case {hecate_om:macula_client(), hecate_om_identity:realm()} of
        {{ok, Pool}, {ok, Realm}} ->
            published(Topic, catch macula:publish(Pool, Realm, Topic, Fact));
        _DarkOrNoRealm ->
            ok
    end.

%% Since macula 6.0.0 a frame the wire cannot carry fails its SENDER with a
%% reason rather than dying silently. Discarding that reason is how a service
%% whose facts are all being rejected comes to look like a service with nothing
%% to say.
published(_Topic, ok) ->
    ok;
published(Topic, Refused) ->
    logger:warning("[sentinel] publish ~s REFUSED: ~p", [Topic, Refused]),
    ok.
