%%% @doc The threat read model — aggregation and the cross-border judgement call.
-module(threat_model_tests).
-include_lib("eunit/include/eunit.hrl").

setup() ->
    ok = application:unset_env(hecate_sentinel, event_store_id),
    {ok, Pid} = hecate_sentinel_threats:start_link(),
    Pid.

cleanup(Pid) -> gen_server:stop(Pid).

model_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
         [ one_country_is_noted()
         , second_country_crosses_the_border()
         , attempts_and_usernames_aggregate()
         , cross_border_list_is_the_campaigns()
         ]
     end}.

sighting(Ip, Warden, Attempts, Users) ->
    #{source_ip => Ip, reporter => Warden, service => <<"ssh">>,
      attempts => Attempts, usernames => Users,
      at => erlang:system_time(millisecond)}.

one_country_is_noted() ->
    R = hecate_sentinel_threats:record_sighting(
          sighting(<<"1.1.1.1">>, <<"warden-de">>, 20, [<<"root">>])),
    ?_assertEqual(noted, R).

%% The whole point: an IP becomes interesting the moment a SECOND country sees
%% it. That transition is what wakes the generals.
second_country_crosses_the_border() ->
    hecate_sentinel_threats:record_sighting(
      sighting(<<"2.2.2.2">>, <<"warden-de">>, 20, [<<"root">>])),
    R = hecate_sentinel_threats:record_sighting(
          sighting(<<"2.2.2.2">>, <<"warden-fr">>, 15, [<<"admin">>])),
    [ ?_assertEqual(crossed_border, R)
    , ?_assert(lists:any(fun(Row) -> maps:get(source_ip, Row) =:= <<"2.2.2.2">> end,
                         hecate_sentinel_threats:cross_border())) ].

attempts_and_usernames_aggregate() ->
    hecate_sentinel_threats:record_sighting(
      sighting(<<"3.3.3.3">>, <<"warden-de">>, 20, [<<"root">>, <<"admin">>])),
    hecate_sentinel_threats:record_sighting(
      sighting(<<"3.3.3.3">>, <<"warden-fr">>, 30, [<<"admin">>, <<"oracle">>])),
    {ok, Row} = hecate_sentinel_threats:get(<<"3.3.3.3">>),
    [ ?_assertEqual(50, maps:get(total_attempts, Row))
    , ?_assertEqual([<<"admin">>, <<"oracle">>, <<"root">>],
                    lists:sort(maps:get(usernames, Row)))
    , ?_assertEqual(2, maps:size(maps:get(wardens, Row))) ].

cross_border_list_is_the_campaigns() ->
    %% 4.4.4.4 seen once (noise), 5.5.5.5 seen twice (campaign).
    hecate_sentinel_threats:record_sighting(
      sighting(<<"4.4.4.4">>, <<"warden-de">>, 5, [])),
    hecate_sentinel_threats:record_sighting(
      sighting(<<"5.5.5.5">>, <<"warden-de">>, 5, [])),
    hecate_sentinel_threats:record_sighting(
      sighting(<<"5.5.5.5">>, <<"warden-it">>, 5, [])),
    Ips = [maps:get(source_ip, R) || R <- hecate_sentinel_threats:cross_border()],
    [ ?_assert(lists:member(<<"5.5.5.5">>, Ips))
    , ?_assertNot(lists:member(<<"4.4.4.4">>, Ips)) ].
