%%% @doc Aggregate for one threat sighting (`sight-{id}').
%%%
%%% One stream per sighting, one event. The stream exists because a sighting is
%%% EVIDENCE: an abuse report to a hosting provider is only as good as the
%%% record behind it, and this record is immutable, timestamped, and signed to
%%% the sentinel that saw it. Reuses sighting_state (no fold).
-module(threat_aggregate).
-behaviour(evoq_aggregate).

-export([init/1, execute/2, apply/2, state_module/0, stream_id/1]).

-spec state_module() -> module().
state_module() -> sighting_state.

init(AggregateId) ->
    {ok, sighting_state:new(AggregateId)}.

-spec stream_id(binary()) -> binary().
stream_id(Id) when is_binary(Id) ->
    <<"sight-", Id/binary>>.

execute(State, #{command_type := <<"report_threat">>} = Payload) ->
    unless_recorded(State, Payload);
execute(_State, _Payload) ->
    {error, unknown_command}.

%% A sighting stream holds exactly ONE event, because a sighting is one
%% observation. If the stream already has it, this delivery is a duplicate of an
%% observation we already hold, and the honest answer is to record nothing.
%%
%% `{ok, []}' is the sanctioned no-op: evoq_aggregate:append_events/5 has an
%% explicit empty-list clause returning `{ok, 0}'. It is NOT an error — the
%% caller asked us to record a fact that is already recorded, and it is.
%%
%% This only bites now that sighting ids are derived from the observation
%% (see ingest_warden_reports:sighting_id/5). While ids were random, every
%% redelivery addressed a fresh stream and no guard here could have seen it.
unless_recorded(#{recorded := true}, _Payload) ->
    {ok, []};
unless_recorded(_State, Payload) ->
    maybe_report_threat:handle_from_map(Payload).

%% Delegate to the state module, which is the whole reason state_module/0
%% exists. This used to discard the event and return State unchanged, so the
%% aggregate replayed to an empty state on every load and could never tell a
%% recorded sighting from a new one.
apply(State, Event) ->
    sighting_state:apply_event(State, Event).
