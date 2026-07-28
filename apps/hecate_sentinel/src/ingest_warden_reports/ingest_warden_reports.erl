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
-export([outcome/2]).  %% exported for tests
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(THREAT_TOPIC,   <<"warden/threats">>).
-define(ENSNARED_TOPIC, <<"warden/ensnared">>).
-define(RESUB_MS, 5_000).
-define(HEARTBEAT_MS, 60_000).

%% `epoch' and `seq' stamp the enriched sighting contract.
%%
%% Not seeded from the event log. `epoch' is set once per boot and `seq' counts
%% RECORDED sightings within that boot, so a consumer that sees the epoch change
%% knows the sentinel restarted and that no continuity is claimed across it.
%% Seeding a single counter from the log instead would have made the sequence
%% depend on the rebuild being whole — and a truncated rebuild would then hand
%% consumers a sequence that silently jumps backwards, which is worse than
%% having none. Same {epoch, seq} shape hecate-grid stamps on observations.
-record(st, {threats  :: reference() | undefined,
             ensnared :: reference() | undefined,
             epoch    :: integer(),
             seq = 0  :: non_neg_integer()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    self() ! subscribe,
    erlang:send_after(?HEARTBEAT_MS, self(), heartbeat),
    {ok, #st{epoch = erlang:system_time(microsecond)}}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info(subscribe, St) ->
    {noreply, do_subscribe(St)};
handle_info({macula_event, _Ref, Topic, Payload, _Meta}, St) ->
    {noreply, on_fact(Topic, Payload, St)};
handle_info(heartbeat, St) ->
    publish_enriched_fact:heartbeat(stamp(St)),
    erlang:send_after(?HEARTBEAT_MS, self(), heartbeat),
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

on_fact(?THREAT_TOPIC, F, St)   -> on_threat(F, St);
on_fact(?ENSNARED_TOPIC, F, St) -> on_ensnared(F, St);
on_fact(_Topic, _F, St)         -> St.

on_threat(F, St) when is_map(F) ->
    dispatch_sighting(mget(source_ip, F), F, St);
on_threat(_, St) ->
    St.

stamp(#st{epoch = Epoch, seq = Seq}) -> {Epoch, Seq}.

dispatch_sighting(Ip, F, St) when is_binary(Ip) ->
    Reporter = mget(warden, F),
    Label    = mget(label, F),
    Service  = default(mget(service, F), <<"ssh">>),
    At       = default(mget(at, F), erlang:system_time(millisecond)),
    Id = sighting_id(Ip, Label, Reporter, Service, At),
    {ok, Cmd} = report_threat_v1:new(
        #{sighting_id => Id,
          reporter    => Reporter,
          label       => Label,
          source_ip   => Ip,
          service     => Service,
          attempts    => default(mget(attempts, F), 1),
          window_s    => default(mget(window_s, F), 60),
          usernames   => default(mget(usernames, F), []),
          at          => At}),
    emit_if_recorded(catch maybe_report_threat:dispatch(Cmd), Id, F#{at => At}, St);
dispatch_sighting(_Ip, _F, St) ->
    St.

%% Emit only what we actually RECORDED.
%%
%% Since sighting ids became deterministic, a redelivered fact addresses the
%% stream it is already in and threat_aggregate refuses it, returning no events.
%% That is the signal: no event recorded means this is a duplicate observation,
%% so there is nothing new to tell the federation and the sequence must not
%% advance. Without this the seq would count DELIVERIES, and consumers would see
%% phantom activity every time the mesh redelivered.
emit_if_recorded(Result, Id, F, #st{seq = Seq} = St) ->
    emitted(outcome(Result, Seq), Result, Id, F, St).

%% @doc What a dispatch result means for the sequence. Exported for tests.
%%
%% `emit' is a sighting we recorded and have not seen before. `skip' is a
%% duplicate the aggregate refused, which is the same observation arriving
%% twice, so there is nothing new to tell anyone and the sequence must NOT
%% advance — otherwise seq would count deliveries and consumers would see
%% phantom activity every time the mesh redelivered. `failed' is evidence we do
%% not hold.
-spec outcome(term(), non_neg_integer()) ->
    {emit | skip | failed, non_neg_integer()}.
outcome({ok, _Version, [_ | _]}, Seq) -> {emit, Seq + 1};
outcome({ok, _Version, []}, Seq)      -> {skip, Seq};
outcome(_Other, Seq)                  -> {failed, Seq}.

emitted({emit, Next}, _Result, Id, F, St) ->
    Advanced = St#st{seq = Next},
    publish_enriched_fact:sighting(Id, F, stamp(Advanced)),
    Advanced;
emitted({skip, _Seq}, _Result, _Id, _F, St) ->
    St;
emitted({failed, _Seq}, Result, _Id, _F, St) ->
    %% A sighting we could not record is evidence we do not have. Emitting it
    %% anyway would put a fact on the mesh that no re-emission could ever
    %% reproduce, so a cold-started consumer would diverge from a warm one for
    %% good. Say so instead.
    logger:warning("[sentinel] sighting NOT recorded, not emitting: ~p", [Result]),
    St.

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

on_ensnared(F, St) when is_map(F) ->
    ensnare(mget(source_ip, F), mget(held_ms, F), F),
    St;
on_ensnared(_, St) ->
    St.

%% The read model still takes only the IP and the duration — that is all a
%% tarpit tally needs. The FACT keeps the box and the timestamp, which used to
%% be discarded here, because a consumer cannot say which box held an attacker,
%% or when, without them.
ensnare(Ip, HeldMs, F) when is_binary(Ip), is_integer(HeldMs) ->
    hecate_sentinel_threats:record_ensnared(Ip, HeldMs),
    publish_enriched_fact:ensnare(Ip, HeldMs, F);
ensnare(_Ip, _HeldMs, _F) ->
    ok.

default(undefined, Def) -> Def;
default(V, _Def)        -> V.

mget(K, M) -> maps:get(K, M, maps:get(atom_to_binary(K, utf8), M, undefined)).
