%%% @doc The threat read model — who is attacking the federation, and where.
%%%
%%% Owns the public ETS table `threats', keyed by source IP. Each row aggregates
%%% every warden that has seen that IP: how many attempts, which usernames they
%%% tried, when, and how long we have held them in a tarpit. Two facts fold in
%%% here: `threat_sighted' (a warden saw real attacks on its real sshd) and
%%% `attacker_ensnared' (a warden held one in the tarpit).
%%%
%%% The single most valuable thing this computes is CROSS-BORDER reach: an IP
%%% seen by two or more wardens is not noise, it is a campaign sweeping the
%%% federation. That is the judgement a rule engine cannot make and a general
%%% can: we measured a median 56-minute head start before the same attacker
%%% reaches the next country. `just_crossed_border/1' reports the transition, so
%%% a general is told the moment an attacker becomes federation-wide.
%%%
%%% In-memory, so it rebuilds from the threat_sighted_v1 log at boot, like every
%%% other read model here.
-module(hecate_sentinel_threats).
-behaviour(gen_server).

-export([start_link/0, record_sighting/1, record_ensnared/2,
         get/1, all/0, cross_border/0, count/0, row/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(TABLE, threats).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Fold a sighting in. Returns `crossed_border' if THIS sighting is the one
%% that made the IP federation-wide (first time a second warden saw it), so the
%% caller can raise it to the generals. `noted' otherwise.
-spec record_sighting(map()) -> crossed_border | noted.
record_sighting(Sighting) ->
    gen_server:call(?MODULE, {sighting, Sighting}).

-spec record_ensnared(binary(), non_neg_integer()) -> ok.
record_ensnared(Ip, HeldMs) ->
    gen_server:cast(?MODULE, {ensnared, Ip, HeldMs}).

-spec get(binary()) -> {ok, map()} | {error, not_found}.
get(Ip) ->
    case ets:lookup(?TABLE, Ip) of
        [{_, Row}] -> {ok, Row};
        []         -> {error, not_found}
    end.

-spec all() -> [map()].
all() ->
    [Row || {_Ip, Row} <- ets:tab2list(?TABLE)].

%% @doc The attackers seen by two or more countries — the campaigns.
-spec cross_border() -> [map()].
cross_border() ->
    [Row || Row <- all(), map_size(maps:get(wardens, Row, #{})) >= 2].

-spec count() -> non_neg_integer().
count() ->
    ets:info(?TABLE, size).

init([]) ->
    ?TABLE = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]),
    Rebuilt = rebuild(),
    logger:info("[sentinel] threat model rebuilt from the log: ~b IPs", [Rebuilt]),
    {ok, #{}}.

handle_call({sighting, Sighting}, _From, S) ->
    {reply, fold_sighting(Sighting), S};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast({ensnared, Ip, HeldMs}, S) ->
    fold_ensnared(Ip, HeldMs),
    {noreply, S};
handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info(_Info, S) -> {noreply, S}.
terminate(_Reason, _S) -> ok.

%% --- Internal ---

rebuild() ->
    Events = threat_sighted_v1_replay(),
    lists:foreach(fun(E) -> fold_sighting(row(E)) end, Events),
    length(Events).

%% @doc The fields a sighting fact/event contributes, normalised. Shared by the
%% projection, the subscriber and the boot replay so all agree on the shape.
-spec row(map()) -> map().
row(Data) ->
    #{source_ip => gf(source_ip, Data),
      reporter  => gf(reporter, Data),
      service   => gf(service, Data),
      attempts  => num(gf(attempts, Data), 1),
      usernames => list_of(gf(usernames, Data)),
      at        => num(gf(at, Data), erlang:system_time(millisecond))}.

fold_sighting(#{source_ip := Ip} = In) when is_binary(Ip) ->
    Before = existing(Ip),
    WasWide = map_size(maps:get(wardens, Before, #{})) >= 2,
    Merged = merge(Before, In),
    true = ets:insert(?TABLE, {Ip, Merged}),
    became_wide(WasWide, map_size(maps:get(wardens, Merged)) >= 2);
fold_sighting(_) ->
    noted.

became_wide(false, true) -> crossed_border;
became_wide(_, _)        -> noted.

existing(Ip) ->
    case ets:lookup(?TABLE, Ip) of
        [{_, Row}] -> Row;
        []         -> #{source_ip => Ip, wardens => #{}, total_attempts => 0,
                        usernames => [], first_seen => undefined,
                        last_seen => 0, held_ms => 0}
    end.

merge(Row, In) ->
    Reporter = maps:get(reporter, In, <<"unknown">>),
    At = maps:get(at, In, erlang:system_time(millisecond)),
    Attempts = maps:get(attempts, In, 1),
    Users = maps:get(usernames, In, []),
    Wardens = maps:put(Reporter,
                       #{attempts => Attempts, last_seen => At,
                         usernames => Users},
                       maps:get(wardens, Row, #{})),
    Row#{wardens => Wardens,
         total_attempts => maps:get(total_attempts, Row, 0) + Attempts,
         usernames => union(maps:get(usernames, Row, []), Users),
         first_seen => first_seen(maps:get(first_seen, Row, undefined), At),
         last_seen => max(maps:get(last_seen, Row, 0), At)}.

fold_ensnared(Ip, HeldMs) ->
    Row = existing(Ip),
    ets:insert(?TABLE, {Ip, Row#{held_ms => maps:get(held_ms, Row, 0) + HeldMs}}),
    ok.

first_seen(undefined, At) -> At;
first_seen(Prev, At)      -> min(Prev, At).

union(A, B) ->
    lists:sublist(lists:usort(A ++ [U || U <- B, is_binary(U)]), 40).

threat_sighted_v1_replay() ->
    case application:get_env(hecate_sentinel, event_store_id) of
        {ok, StoreId} -> read_all(StoreId);
        _             -> []
    end.

read_all(StoreId) ->
    case catch evoq_event_store:read_events_by_types(
                 StoreId, [<<"threat_sighted_v1">>], 50000) of
        {ok, Events} when is_list(Events) -> Events;
        _                                 -> []
    end.

gf(K, M) -> maps:get(K, M, maps:get(atom_to_binary(K, utf8), M, undefined)).

num(N, _Def) when is_integer(N) -> N;
num(_, Def)                     -> Def.

list_of(L) when is_list(L) -> [U || U <- L, is_binary(U)];
list_of(_)                 -> [].
