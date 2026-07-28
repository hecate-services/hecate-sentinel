%%% @doc Federation subscriber for warden reports.
%%%
%%% The wardens on the public boxes publish two facts: `threat_sighted' (real
%%% attacks on a box's real sshd) and `attacker_ensnared' (the tarpit held one).
%%% This hears both. A sighting is dispatched as a report_threat command, so it
%%% is recorded as a threat_sighted_v1 domain event — the immutable, attributable
%%% evidence chain an abuse report is built from, kept HERE on the beam side, not
%%% on the attacked box. An ensnare updates the tarpit tally directly (lower
%%% stakes, no evidence needed).
%%%
%%% Re-subscribes on teardown. Degrades safely while the mesh is dark.
-module(ingest_warden_reports).
-behaviour(gen_server).

-export([start_link/0, sighting_id/5]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(THREAT_TOPIC,   <<"warden/threats">>).
-define(ENSNARED_TOPIC, <<"warden/ensnared">>).
-define(RESUB_MS, 5_000).

-record(st, {threats :: reference() | undefined,
             ensnared :: reference() | undefined}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    self() ! subscribe,
    {ok, #st{}}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info(subscribe, St) ->
    {noreply, do_subscribe(St)};
handle_info({macula_event, _Ref, Topic, Payload, _Meta}, St) ->
    _ = on_fact(Topic, Payload),
    {noreply, St};
handle_info({macula_event_gone, _Ref, _Reason}, St) ->
    self() ! subscribe,
    {noreply, St#st{threats = undefined, ensnared = undefined}};
handle_info(_Info, St) ->
    {noreply, St}.

terminate(_Reason, _St) -> ok.

%% --- Internal ---

do_subscribe(St) ->
    case {hecate_om:macula_client(), hecate_om_identity:realm()} of
        {{ok, Pool}, {ok, Realm}} ->
            T = sub(Pool, Realm, ?THREAT_TOPIC),
            E = sub(Pool, Realm, ?ENSNARED_TOPIC),
            maybe_resubscribe(T, E),
            St#st{threats = T, ensnared = E};
        _DarkOrNoRealm ->
            erlang:send_after(?RESUB_MS, self(), subscribe),
            St
    end.

%% A subscribe that threw (e.g. the pool's 5s call timing out at boot)
%% leaves the ref `undefined'. Without re-arming the timer the sentinel
%% stays silently deaf to the wardens forever — re-try until both hold.
maybe_resubscribe(T, E) when T =:= undefined; E =:= undefined ->
    erlang:send_after(?RESUB_MS, self(), subscribe);
maybe_resubscribe(_T, _E) ->
    ok.

sub(Pool, Realm, Topic) ->
    case catch macula:subscribe(Pool, Realm, Topic, self()) of
        {ok, Ref} -> Ref;
        _         -> undefined
    end.

on_fact(?THREAT_TOPIC, F)   -> on_threat(F);
on_fact(?ENSNARED_TOPIC, F) -> on_ensnared(F);
on_fact(_Topic, _F)         -> ok.

on_threat(F) when is_map(F) ->
    dispatch_sighting(mget(source_ip, F), F);
on_threat(_) ->
    ok.

dispatch_sighting(Ip, F) when is_binary(Ip) ->
    Reporter = mget(warden, F),
    Label    = mget(label, F),
    Service  = default(mget(service, F), <<"ssh">>),
    At       = default(mget(at, F), erlang:system_time(millisecond)),
    {ok, Cmd} = report_threat_v1:new(
        #{sighting_id => sighting_id(Ip, Label, Reporter, Service, At),
          reporter    => Reporter,
          label       => Label,
          source_ip   => Ip,
          service     => Service,
          attempts    => default(mget(attempts, F), 1),
          window_s    => default(mget(window_s, F), 60),
          usernames   => default(mget(usernames, F), []),
          at          => At}),
    catch maybe_report_threat:dispatch(Cmd),
    ok;
dispatch_sighting(_Ip, _F) ->
    ok.

%% The identity of a sighting is the OBSERVATION, not the delivery of it.
%%
%% This was `crypto:strong_rand_bytes/1', minted fresh on every mesh delivery,
%% so a redelivered fact became a second event and inflated the evidence log
%% permanently. Deriving the id from the observation means redelivery and store
%% replay both land on the same stream, where threat_aggregate refuses the
%% duplicate.
%%
%% `at' is the warden's own stamp, applied once at publish, so it survives
%% redelivery unchanged. `service' is in the key because two sensors on one
%% warden can report the same IP in the same millisecond for different
%% services; without it one of them would be silently lost. The warden
%% component follows hecate_sentinel_threats:warden_key/2 exactly — an id that
%% disagreed with the correlation key would be a silent bug.
%%
%% One honest limit: a warden that sends no `at' gets the current time, so its
%% sightings are not deduplicable. Every warden sends one today.
sighting_id(Ip, Label, Reporter, Service, At) ->
    Warden = hecate_sentinel_threats:warden_key(Label, default(Reporter, <<"unknown">>)),
    Material = [Ip, 0, Warden, 0, Service, 0, integer_to_binary(At)],
    <<Id:16/binary, _/binary>> = crypto:hash(sha256, Material),
    binary:encode_hex(Id, lowercase).

on_ensnared(F) when is_map(F) ->
    ensnare(mget(source_ip, F), mget(held_ms, F));
on_ensnared(_) ->
    ok.

ensnare(Ip, HeldMs) when is_binary(Ip), is_integer(HeldMs) ->
    hecate_sentinel_threats:record_ensnared(Ip, HeldMs);
ensnare(_Ip, _HeldMs) ->
    ok.

default(undefined, Def) -> Def;
default(V, _Def)        -> V.

mget(K, M) -> maps:get(K, M, maps:get(atom_to_binary(K, utf8), M, undefined)).
