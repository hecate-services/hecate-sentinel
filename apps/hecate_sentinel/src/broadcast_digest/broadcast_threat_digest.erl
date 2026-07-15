%%% @doc A paced heartbeat for the society: a periodic THREAT DIGEST broadcast.
%%%
%%% The cross-border alert in `threat_sighted_v1_to_threats' only fires the
%%% moment an attacker crosses into a second country. Between crossings the
%%% sentinel is silent, and a mind with no input manufactures its own make-work
%%% (re-verifying its own state, burning tokens). This desk gives the society a
%%% steady, real heartbeat: on a timer, and ONLY when the landscape has actually
%%% moved, it broadcasts a digest of the current threat picture — top sources,
%%% attempt volume, active campaigns — and asks the minds for a read.
%%%
%%% Change-gated on purpose: re-sending an identical picture would just make the
%%% minds re-reason about the same thing. A digest goes out only when sources
%%% grew or attempts moved past a small delta, so what reaches the minds is
%%% always a genuine change to weigh.
-module(broadcast_threat_digest).
-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(BROADCAST_TOPIC, <<"spartan/broadcast">>).
-define(SENTINEL_DID, <<"did:web:macula.io#sentinel">>).
-define(DEFAULT_INTERVAL_MS, 1800000).   %% 30 minutes
-define(ATTEMPTS_DELTA, 50).             %% min attempt growth to count as "moved"
-define(TOP_N, 3).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    schedule(),
    {ok, #{last => undefined}}.

handle_call(_Req, _From, S) -> {reply, ok, S}.
handle_cast(_Msg, S)        -> {noreply, S}.

handle_info(digest, S) ->
    S2 = maybe_publish(S),
    schedule(),
    {noreply, S2};
handle_info(_Info, S) ->
    {noreply, S}.

terminate(_Reason, _S) -> ok.

%% --- Internals ---

schedule() ->
    erlang:send_after(interval_ms(), self(), digest).

interval_ms() ->
    application:get_env(hecate_sentinel, digest_interval_ms, ?DEFAULT_INTERVAL_MS).

maybe_publish(S) ->
    All = hecate_sentinel_threats:all(),
    Sig = signature(All),
    case {All, changed(Sig, maps:get(last, S))} of
        {[], _}    -> S;                          %% nothing sensed; stay quiet
        {_, false} -> S;                          %% steady state; do not re-stimulate
        {_, true}  -> catch publish(All), S#{last => Sig}
    end.

%% A landscape "moved" if a new source appeared or attempts grew past a small
%% delta since the last digest. The first digest always goes out.
signature(All) ->
    {length(All), total_attempts(All)}.

changed(_New, undefined)          -> true;
changed({S2, A2}, {S1, A1})       -> S2 =/= S1 orelse (A2 - A1) >= ?ATTEMPTS_DELTA.

publish(All) ->
    Top       = lists:sublist(sort_by_attempts(All), ?TOP_N),
    Campaigns = hecate_sentinel_threats:cross_border(),
    Body = iolist_to_binary(
        [<<"[THREAT DIGEST] ">>,
         integer_to_binary(length(All)), <<" active sources, ">>,
         integer_to_binary(total_attempts(All)), <<" attempts across ">>,
         integer_to_binary(box_count(All)), <<" of our boxes. Busiest: ">>,
         join_top(Top),
         campaigns_line(Campaigns),
         <<". Steady state, or is something escalating? Your read.">>]),
    Fact = #{type    => spartan_broadcast,
             msg_id  => digest_id(),
             from    => ?SENTINEL_DID,
             body    => Body,
             sent_at => erlang:system_time(millisecond)},
    publish_fact(Fact).

sort_by_attempts(All) ->
    lists:sort(fun(A, B) -> attempts(A) >= attempts(B) end, All).

attempts(Row)      -> maps:get(total_attempts, Row, 0).
total_attempts(All) -> lists:sum([attempts(R) || R <- All]).

box_count(All) ->
    Keys = [maps:keys(maps:get(wardens, R, #{})) || R <- All],
    length(lists:usort(lists:append(Keys))).

join_top(Top) ->
    iolist_to_binary(lists:join(<<"; ">>,
        [[Ip, <<" (">>, origin(R), <<", ">>,
          integer_to_binary(attempts(R)), <<" attempts)">>]
         || #{source_ip := Ip} = R <- Top])).

origin(Row) ->
    Geo = maps:get(geo, Row, #{}),
    case maps:get(country, Geo, undefined) of
        C when is_binary(C) -> C;
        _                   -> <<"unknown origin">>
    end.

campaigns_line([]) ->
    <<". No cross-border campaigns right now">>;
campaigns_line(Campaigns) ->
    Ips = lists:join(<<", ">>, [Ip || #{source_ip := Ip} <- Campaigns]),
    iolist_to_binary([<<". Cross-border campaigns active: ">>, Ips]).

%% Each digest is distinct (timestamped id) so the minds treat it as new, unlike
%% the per-IP [THREAT] alert which dedups on re-crossing.
digest_id() ->
    <<"digest-", (integer_to_binary(erlang:system_time(millisecond)))/binary>>.

publish_fact(Fact) ->
    case {hecate_om:macula_client(), hecate_om_identity:realm()} of
        {{ok, Pool}, {ok, Realm}} ->
            catch macula:publish(Pool, Realm, ?BROADCAST_TOPIC, Fact),
            ok;
        _DarkOrNoRealm ->
            ok
    end.
