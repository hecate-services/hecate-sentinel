%%% @doc The sentinel's public contract, pinned.
%%%
%%% One enriched fact out per warden fact in, at the SAME grain. The contract
%%% this replaces carried cumulative per-IP state, whose `boxes' field was a
%%% union over all time — so nothing downstream could say which box saw an
%%% attacker when. These pin the parts that made it useless for anything but a
%%% map. See plans/DESIGN_ENRICHED_FACT_CONTRACT.md.
-module(enriched_fact_tests).
-include_lib("eunit/include/eunit.hrl").

-define(IP, <<"203.0.113.7">>).
-define(AT, 1785215553616).
-define(STAMP, {1785215000000000, 41}).

%% THE POINT OF THE WHOLE CHANGE. A sighting names the ONE box that reported it
%% and the attempts IT saw, not a union over every box and all time.
sighting_carries_the_reporting_box_test() ->
    F = sighting_fact(),
    ?assertEqual(<<"helsinki">>, maps:get(box, F)),
    ?assertEqual(5, maps:get(attempts, F)),
    ?assertEqual(?AT, maps:get(at, F)),
    ?assertEqual(?IP, maps:get(ip, F)),
    %% no accumulated set of boxes anywhere in the fact
    ?assertEqual(error, maps:find(boxes, F)).

%% Both were dropped on the floor before: tenant_id never left ingest, and the
%% warden's DID was not on the published contract at all. Without them the
%% commons cannot attribute a sighting to whoever contributed it.
sighting_carries_attribution_test() ->
    F = sighting_fact(),
    ?assertEqual(<<"hecate">>, maps:get(tenant_id, F)),
    ?assertEqual(<<"did:web:example#warden">>, maps:get(reporter, F)).

sighting_carries_the_stamp_test() ->
    {Epoch, Seq} = ?STAMP,
    F = sighting_fact(),
    ?assertEqual(Epoch, maps:get(epoch, F)),
    ?assertEqual(Seq, maps:get(seq, F)).

%% An ensnare is not evented, so nothing can number it honestly. Saying `seq'
%% here with a number that counts sightings would imply a continuity that does
%% not exist.
ensnare_carries_no_seq_test() ->
    F = publish_enriched_fact:ensnare_fact(?IP, 4200, warden_fact()),
    ?assertEqual(error, maps:find(seq, F)),
    ?assertEqual(error, maps:find(epoch, F)).

%% ingest_warden_reports:ensnare/2 discarded both of these, so a consumer could
%% not say which box held an attacker, or when.
ensnare_carries_box_and_time_test() ->
    F = publish_enriched_fact:ensnare_fact(?IP, 4200, warden_fact()),
    ?assertEqual(<<"helsinki">>, maps:get(box, F)),
    ?assertEqual(?AT, maps:get(at, F)),
    ?assertEqual(4200, maps:get(held_ms, F)).

%% Absent enrichment must be ABSENT, not a key holding `undefined', or every
%% consumer has to special-case the atom.
unknown_fields_are_omitted_not_undefined_test() ->
    F = sighting_fact(),
    ?assertEqual([], [K || {K, V} <- maps:to_list(F), V =:= undefined]).

heartbeat_carries_the_stamp_and_nothing_else_test() ->
    {Epoch, Seq} = ?STAMP,
    F = publish_enriched_fact:heartbeat_fact(?STAMP),
    ?assertEqual(Epoch, maps:get(epoch, F)),
    ?assertEqual(Seq, maps:get(seq, F)),
    ?assertEqual(sentinel_heartbeat, maps:get(type, F)),
    ?assertEqual(error, maps:find(ip, F)).

%% --- the sequence ---

%% seq counts RECORDED sightings, not deliveries. A redelivered fact is refused
%% by the aggregate (no events), and must not advance the sequence: if it did,
%% consumers would see phantom activity every time the mesh redelivered.
seq_advances_only_on_a_recorded_sighting_test() ->
    ?assertEqual({emit, 42}, ingest_warden_reports:outcome({ok, 0, [event]}, 41)),
    ?assertEqual({skip, 41}, ingest_warden_reports:outcome({ok, 0, []}, 41)).

%% Evidence we do not hold must not be announced as though we did.
a_failed_dispatch_neither_emits_nor_advances_test() ->
    ?assertEqual({failed, 41}, ingest_warden_reports:outcome({error, timeout}, 41)),
    %% dispatch is wrapped in `catch', so an exception arrives as a raw term
    ?assertEqual({failed, 41}, ingest_warden_reports:outcome({'EXIT', boom}, 41)).

%% --- helpers ---

sighting_fact() ->
    publish_enriched_fact:sighting_fact(<<"abc123">>, warden_fact(), ?STAMP).

warden_fact() ->
    #{source_ip => ?IP,
      warden    => <<"did:web:example#warden">>,
      label     => <<"helsinki">>,
      tenant_id => <<"hecate">>,
      service   => <<"ssh">>,
      attempts  => 5,
      window_s  => 300,
      usernames => [<<"root">>, <<"admin">>],
      at        => ?AT}.
