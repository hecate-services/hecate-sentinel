%%% @doc Projection: threat_sighted_v1 -> the threat read model, and — when an
%%% attacker crosses a border — an alert BROADCAST to the society.
%%%
%%% This is the seam where dumb sensing becomes reasoning. A warden reports raw
%%% facts; the read model aggregates them; and the moment an IP is seen by a
%%% SECOND country, the projection alerts the whole society.
%%%
%%% It alerts through hecate-spartan's PUBLIC broadcast primitive: it publishes a
%%% `spartan/broadcast' fact, and every hecate-spartan node delivers it to its
%%% local minds as a message. This service never reaches into hecate-spartan — it
%%% is a peer on the mesh. That is what keeps the society substrate agnostic: it
%%% knows how to route messages between minds and nothing about attacks.
%%%
%%% A rule engine blocks on a count. A general reads the usernames tried, weighs
%%% whether it looks targeted or like botnet noise, and says which in the agora.
%%% That judgement is the thing this whole system exists to produce.
-module(threat_sighted_v1_to_threats).
-behaviour(evoq_projection).

-export([interested_in/0, init/1, project/4]).

-define(TABLE, threat_projection_checkpoint).
-define(BROADCAST_TOPIC, <<"spartan/broadcast">>).
-define(ATTACK_TOPIC, <<"sentinel/attack">>).
-define(CAMPAIGN_TOPIC, <<"sentinel/campaign">>).
-define(SENTINEL_DID, <<"did:web:macula.io#sentinel">>).

interested_in() ->
    [<<"threat_sighted_v1">>].

init(_Config) ->
    {ok, RM} = evoq_read_model:new(evoq_read_model_ets, #{name => ?TABLE}),
    {ok, #{}, RM}.

project(#{data := Data} = Event, _Metadata, State, RM) ->
    case get_event_type(Event) of
        <<"threat_sighted_v1">> -> record(Data, State, RM);
        _                       -> {ok, State, RM}
    end;
project(_Event, _Metadata, State, RM) ->
    {ok, State, RM}.

record(Data, State, RM) ->
    Row = hecate_sentinel_threats:row(Data),
    Crossed = hecate_sentinel_threats:record_sighting(Row),
    Ip = maps:get(source_ip, Row),
    announce(Crossed, Ip),
    {ok, RM2} = evoq_read_model:put(Ip, noted, RM),
    {ok, State, RM2}.

%% Two audiences, two facts. Every sighting is published enriched to
%% `sentinel/attack' for observers (the map's live layer). Only a CROSS-BORDER
%% attacker becomes a `sentinel/campaign' AND reaches the minds: a single
%% country's noise is a firehose no general should read; a campaign sweeping the
%% federation is exactly what they should weigh in on.
announce(Crossed, Ip) when is_binary(Ip) ->
    emit(Crossed, hecate_sentinel_threats:get(Ip));
announce(_Crossed, _Ip) ->
    ok.

emit(Crossed, {ok, Full}) ->
    publish_fact(?ATTACK_TOPIC, attack_fact(Full)),
    emit_crossed(Crossed, Full);
emit(_Crossed, _NotFound) ->
    ok.

emit_crossed(crossed_border, Full) ->
    publish_fact(?CAMPAIGN_TOPIC, campaign_fact(Full)),
    broadcast_alert(Full);
emit_crossed(noted, _Full) ->
    ok.

%% The enriched public contract for a single attacker's current state. Observers
%% upsert by IP, so a boot-replay burst just re-paints existing points.
attack_fact(Full) ->
    Geo = maps:get(geo, Full, #{}),
    prune(#{type          => sentinel_attack,
            ip            => maps:get(source_ip, Full),
            country_iso   => g(country_iso, Geo),
            country       => g(country, Geo),
            city          => g(city, Geo),
            lat_e6        => e6(g(lat, Geo)),
            lng_e6        => e6(g(lng, Geo)),
            asn           => g(asn, Geo),
            asn_org       => g(asn_org, Geo),
            net_type      => g(net_type, Geo),
            boxes         => maps:keys(maps:get(wardens, Full, #{})),
            service       => <<"ssh">>,
            total_attempts => maps:get(total_attempts, Full, 0),
            usernames     => lists:sublist(maps:get(usernames, Full, []), 20),
            first_seen    => maps:get(first_seen, Full, 0),
            last_seen     => maps:get(last_seen, Full, 0),
            at            => erlang:system_time(millisecond)}).

%% A cross-border correlation: the same attacker, now on two or more of our
%% boxes. `head_start_ms' is how long the federation knew before the latest box
%% was hit — the propagation lead the mesh buys us.
campaign_fact(Full) ->
    Geo = maps:get(geo, Full, #{}),
    Boxes = maps:keys(maps:get(wardens, Full, #{})),
    First = maps:get(first_seen, Full, 0),
    Last = maps:get(last_seen, Full, 0),
    prune(#{type          => sentinel_campaign,
            ip            => maps:get(source_ip, Full),
            country_iso   => g(country_iso, Geo),
            country       => g(country, Geo),
            city          => g(city, Geo),
            lat_e6        => e6(g(lat, Geo)),
            lng_e6        => e6(g(lng, Geo)),
            asn           => g(asn, Geo),
            asn_org       => g(asn_org, Geo),
            net_type      => g(net_type, Geo),
            boxes         => Boxes,
            box_count     => length(Boxes),
            head_start_ms => max(0, Last - First),
            total_attempts => maps:get(total_attempts, Full, 0),
            usernames     => lists:sublist(maps:get(usernames, Full, []), 20),
            at            => erlang:system_time(millisecond)}).

g(K, M) -> maps:get(K, M, undefined).

%% Coordinates go on the wire as micro-degree INTEGERS, never floats: the mesh
%% CBOR payload path drops raw floats (the same class of bug as the negative-int
%% drop). Integers survive intact; the realm divides by 1e6 to plot.
e6(F) when is_float(F)   -> round(F * 1000000);
e6(N) when is_integer(N) -> N * 1000000;
e6(_)                    -> undefined.

prune(M) -> maps:filter(fun(_K, V) -> V =/= undefined end, M).

broadcast_alert(Full) ->
    Ip = maps:get(source_ip, Full),
    Where = maps:keys(maps:get(wardens, Full, #{})),
    Users = maps:get(usernames, Full, []),
    Body = iolist_to_binary(
        [<<"[THREAT] ">>, Ip, origin(maps:get(geo, Full, #{})),
         <<" is now attacking ">>, integer_to_binary(length(Where)),
         <<" of our locations (">>, join(Where),
         <<"), ">>, integer_to_binary(maps:get(total_attempts, Full, 0)),
         <<" attempts. Usernames tried: ">>, join(Users),
         <<". Is this a targeted campaign or botnet noise? Your read.">>]),
    Fact = #{type    => spartan_broadcast,
             msg_id  => <<"threat-", Ip/binary>>,
             from    => ?SENTINEL_DID,
             body    => Body,
             sent_at => erlang:system_time(millisecond)},
    publish_fact(?BROADCAST_TOPIC, Fact).

publish_fact(Topic, Fact) ->
    case {hecate_om:macula_client(), hecate_om_identity:realm()} of
        {{ok, Pool}, {ok, Realm}} ->
            catch macula:publish(Pool, Realm, Topic, Fact),
            ok;
        _DarkOrNoRealm ->
            ok
    end.

%% "(Moscow, Russia · AS12345 Selectel)" — the context a mind reasons over: a
%% hosting ASN is a rented attack box, a residential ISP is a compromised home
%% device, and a name that matches ours turns spray into a targeted probe.
origin(Geo) when map_size(Geo) =:= 0 -> <<>>;
origin(Geo) ->
    Place = [P || P <- [maps:get(city, Geo, undefined),
                        maps:get(country, Geo, undefined)], is_binary(P)],
    Net = net(maps:get(asn_org, Geo, undefined), maps:get(asn, Geo, undefined)),
    Parts = [X || X <- [lists:join(<<", ">>, Place), Net], X =/= [], X =/= <<>>],
    wrap(Parts).

net(Org, Asn) when is_binary(Org) -> [as(Asn), Org];
net(_Org, _Asn)                   -> [].

as(N) when is_integer(N) -> [<<"AS">>, integer_to_binary(N), <<" ">>];
as(_)                    -> [].

wrap([])    -> <<>>;
wrap(Parts) ->
    iolist_to_binary([<<" (">>, lists:join(<<" \xc2\xb7 ">>, Parts), <<")">>]).

join([])    -> <<"(none captured)">>;
join(Users) -> iolist_to_binary(lists:join(<<", ">>, lists:sublist(Users, 12))).

get_event_type(#{event_type := T}) -> T;
get_event_type(_)                  -> undefined.
