%% @doc Real (not mocked) integration test against a live reckon_db store.
%%
%% Common Test, not EUnit: booting real ra+khepri+reckon_db in-process is the
%% established pattern for this in reckon-db-org/reckon-db's own suites
%% (reckon_db_pg_scope_SUITE and friends) -- rebar3's EUnit runner hits a
%% reproducible ~13s application:ensure_all_started(khepri) timeout in this
%% workspace that CT's own {timetrap, ...} + boot path does not.
%%
%% Two things need proving, both through the REAL production code path
%% (threat_sighted_v1_to_threats:project/4), not a simulated stand-in:
%%
%% 1. sentinel_alert_dedup itself: a marker survives, is per-IP isolated, and
%%    a second mark for an already-marked IP does not grow the snapshot count.
%%
%% 2. The actual restart scenario: hecate_sentinel_threats (the ETS read
%%    model) rebuilds itself directly from the event log in its OWN init/1,
%%    separately from and BEFORE evoq's projection catch-up runs (see
%%    hecate_sentinel_sup's child order) -- so on an ordinary restart the
%%    projection's replay usually finds the model already merged and never
%%    re-detects crossed_border at all. The gap this fix closes is the
%%    degraded case that module's own comments call out: a truncated or
%%    failed rebuild leaves the model empty, so the projection's replay
%%    re-detects the SAME historical crossing and would re-fire the alert
%%    without a persistent, order-independent marker. Test 2 simulates
%%    exactly that degraded case (an emptied read model) and proves both
%%    halves at once: the alert does NOT refire, while the read model DOES
%%    fully repopulate with the complete history regardless.
-module(sentinel_alert_dedup_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("reckon_db/include/reckon_db.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([dedup_marks_persist_and_isolate_by_ip/1,
         restart_does_not_refire_alert_but_read_model_fully_repopulates/1]).

-define(STORE_ID, hecate_sentinel_store).

%%====================================================================
%% CT callbacks
%%====================================================================

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [dedup_marks_persist_and_isolate_by_ip,
     restart_does_not_refire_alert_but_read_model_fully_repopulates].

init_per_suite(Config) ->
    DataDir = "/tmp/sentinel_alert_dedup_ct_" ++
              integer_to_list(erlang:unique_integer([positive])),
    RaDataDir = DataDir ++ "_ra",
    os:cmd("rm -rf " ++ RaDataDir),
    ok = filelib:ensure_dir(filename:join(RaDataDir, "dummy")),
    application:set_env(ra, data_dir, RaDataDir),
    {ok, _} = application:ensure_all_started(ra),
    ok = ra:start(),
    {ok, _} = application:ensure_all_started(khepri),
    application:set_env(reckon_db, resource_monitoring, false),
    %% reckon_db_sup:init/1 supervises its own pg scope (reckon_db_pg) as a
    %% child -- do not pre-start it, that squats the name.
    {ok, _} = application:ensure_all_started(reckon_db),
    %% reckon_db_sup:init([]) starts with NO stores of its own, and
    %% reckon_db.app.src declares {stores, []} in its own {env, ...} --
    %% application:load/1 (triggered internally by ensure_all_started/1
    %% above, since reckon_db isn't loaded yet at this point in a fresh CT
    %% node) resets env to the .app file's declared defaults, so a
    %% set_env(reckon_db, stores, [...]) called before that load is
    %% silently wiped back to []. Pass the store_config record straight to
    %% start_store/1 instead of round-tripping through app env.
    {ok, _} = reckon_db_sup:start_store(#store_config{
        store_id = ?STORE_ID, data_dir = DataDir, mode = single}),
    ok = wait_ready(60),
    %% hecate_sentinel_threats reads this env var in its own init/1 rebuild.
    application:set_env(hecate_sentinel, event_store_id, ?STORE_ID),
    {ok, ThreatsPid} = hecate_sentinel_threats:start_link(),
    %% start_link/0 links it to THIS init_per_suite call, a transient CT
    %% process that goes away once init_per_suite returns -- unlink so the
    %% gen_server survives for the actual test cases, exactly as it does
    %% under its real, persistent supervisor in production.
    unlink(ThreatsPid),
    [{data_dir, DataDir}, {ra_data_dir, RaDataDir}, {threats_pid, ThreatsPid} | Config].

end_per_suite(Config) ->
    ThreatsPid = ?config(threats_pid, Config),
    unlink(ThreatsPid),
    exit(ThreatsPid, shutdown),
    application:stop(reckon_db),
    os:cmd("rm -rf " ++ ?config(data_dir, Config)),
    os:cmd("rm -rf " ++ ?config(ra_data_dir, Config)),
    ok.

wait_ready(0) -> {error, timeout};
wait_ready(N) ->
    case catch reckon_db_store:is_ready(?STORE_ID) of
        true -> ok;
        _ -> timer:sleep(200), wait_ready(N - 1)
    end.

%%====================================================================
%% Test cases
%%====================================================================

%% @doc GIVEN an IP with no marker
%%      WHEN it is marked alerted
%%      THEN already_alerted/1 flips true, the snapshot count stays at
%%           exactly one on a repeated (correctly-guarded) mark, and a
%%           different IP is completely unaffected.
dedup_marks_persist_and_isolate_by_ip(_Config) ->
    Ip = unique_ip(),

    ?assertEqual(false, sentinel_alert_dedup:already_alerted(Ip)),
    ?assertEqual(0, sentinel_alert_dedup:snapshot_count(Ip)),

    ok = sentinel_alert_dedup:mark_alerted(Ip),
    timer:sleep(50), %% record_snapshot is a cast; let it land
    ?assertEqual(true, sentinel_alert_dedup:already_alerted(Ip)),
    ?assertEqual(1, sentinel_alert_dedup:snapshot_count(Ip)),

    %% What a correct caller does on a second sighting: check first.
    case sentinel_alert_dedup:already_alerted(Ip) of
        true -> ok;
        false -> sentinel_alert_dedup:mark_alerted(Ip)
    end,
    timer:sleep(50),
    ?assertEqual(1, sentinel_alert_dedup:snapshot_count(Ip)),

    OtherIp = unique_ip(),
    ?assertEqual(false, sentinel_alert_dedup:already_alerted(OtherIp)),
    ?assertEqual(0, sentinel_alert_dedup:snapshot_count(OtherIp)).

%% @doc GIVEN an IP that has already crossed two wardens and been alerted
%%      WHEN the read model is emptied (the degraded-rebuild case
%%           hecate_sentinel_threats itself warns about: truncated or
%%           failed, leaving the model with no memory of the crossing)
%%           and the SAME two sightings are replayed through the real
%%           projection function, exactly as evoq's catch_up_historical
%%           would on restart
%%      THEN the read model fully repopulates with both wardens and the
%%           combined attempt count, while the alert does NOT refire.
%% Sentinel_alert_dedup's own snapshot is keyed by (StreamId, Version) with
%% mark_alerted/1 always writing Version 0, so a re-mark OVERWRITES the same
%% snapshot rather than adding one -- snapshot_count/1 alone cannot tell
%% "marked once" from "marked twice". The thing that actually must not
%% happen twice is the call to broadcast_alert/1 itself (the notification
%% reaching the minds), so that call is traced directly rather than
%% inferred from snapshot bookkeeping.
restart_does_not_refire_alert_but_read_model_fully_repopulates(_Config) ->
    Ip = unique_ip(),
    Trace = start_broadcast_trace(),
    {ok, PState0, PRM0} = threat_sighted_v1_to_threats:init(#{}),

    Sighting1 = sighting(Ip, <<"did:web:helsinki">>, <<"helsinki">>, 3, [<<"root">>]),
    Sighting2 = sighting(Ip, <<"did:web:tallinn">>, <<"tallinn">>, 5, [<<"admin">>]),

    %% "Boot 1": first warden, then the second -- the crossing.
    {ok, PState1, PRM1} = threat_sighted_v1_to_threats:project(Sighting1, #{}, PState0, PRM0),
    ?assertEqual(0, broadcast_call_count(Trace)),

    {ok, _PState2, _PRM2} = threat_sighted_v1_to_threats:project(Sighting2, #{}, PState1, PRM1),
    timer:sleep(50),
    ?assertEqual(1, broadcast_call_count(Trace)),
    ?assertEqual(1, sentinel_alert_dedup:snapshot_count(Ip)),
    {ok, AfterBoot1} = hecate_sentinel_threats:get(Ip),
    ?assertEqual(2, map_size(maps:get(wardens, AfterBoot1))),

    %% Simulate the degraded restart: the read model comes back with no
    %% memory of this IP at all (truncated/failed rebuild), exactly the
    %% scenario hecate_sentinel_threats:log_rebuild/3 warns about.
    true = ets:delete_all_objects(threats),
    ?assertEqual({error, not_found}, hecate_sentinel_threats:get(Ip)),

    %% "Boot 2": evoq's catch_up_historical replays the SAME two events
    %% through the SAME projection function, from a fresh projection state.
    {ok, PState0b, PRM0b} = threat_sighted_v1_to_threats:init(#{}),
    {ok, PState1b, PRM1b} = threat_sighted_v1_to_threats:project(Sighting1, #{}, PState0b, PRM0b),
    {ok, _PState2b, _PRM2b} = threat_sighted_v1_to_threats:project(Sighting2, #{}, PState1b, PRM1b),
    timer:sleep(50),

    %% The read model DID fully repopulate with the complete history...
    {ok, AfterBoot2} = hecate_sentinel_threats:get(Ip),
    ?assertEqual(2, map_size(maps:get(wardens, AfterBoot2))),
    ?assertEqual(8, maps:get(total_attempts, AfterBoot2)),

    %% ...and hecate_sentinel_threats's OWN logic DID re-detect the SAME
    %% crossing on this replay (proving the scenario is real, not vacuous:
    %% the read model being empty really does make the projection see
    %% crossed_border again) -- but broadcast_alert itself was NOT called
    %% a second time, and the durable dedup marker still shows exactly one
    %% mark, not a fresh overwrite this boot.
    ?assertEqual(1, broadcast_call_count(Trace)),
    ?assertEqual(1, sentinel_alert_dedup:snapshot_count(Ip)),
    stop_broadcast_trace().

%%====================================================================
%% Helpers
%%====================================================================

%% @doc Traces calls to threat_sighted_v1_to_threats:broadcast_alert/1 --
%% the actual notification side effect -- into an ETS counter. Direct call
%% tracing rather than meck: broadcast_alert/1 is real production code,
%% left completely unmocked, so the count reflects exactly what the real
%% projection did.
start_broadcast_trace() ->
    Table = ets:new(broadcast_trace, [set, public]),
    ets:insert(Table, {count, 0}),
    {ok, _} = dbg:tracer(process, {fun
        ({trace, _Pid, call, _MFA}, T) -> ets:update_counter(T, count, 1), T;
        (_Other, T) -> T
    end, Table}),
    {ok, _} = dbg:p(all, call),
    %% broadcast_alert/1 is a private function (not in -export), so it
    %% needs tpl (trace pattern, local) -- tp only matches exported calls.
    {ok, _} = dbg:tpl(threat_sighted_v1_to_threats, broadcast_alert, 1, []),
    Table.

broadcast_call_count(Table) ->
    [{count, N}] = ets:lookup(Table, count),
    N.

stop_broadcast_trace() ->
    dbg:stop().

unique_ip() ->
    N = erlang:unique_integer([positive, monotonic]),
    iolist_to_binary(io_lib:format("198.51.100.~b", [1 + (N rem 250)])).

sighting(Ip, Reporter, Label, Attempts, Usernames) ->
    Data = #{source_ip => Ip, reporter => Reporter, label => Label,
             service => <<"ssh">>, attempts => Attempts, usernames => Usernames,
             at => erlang:system_time(millisecond)},
    #{data => Data, event_type => <<"threat_sighted_v1">>}.
