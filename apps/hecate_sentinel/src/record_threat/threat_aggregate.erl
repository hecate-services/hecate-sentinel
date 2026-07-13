%%% @doc Aggregate for one threat sighting (`sight-{id}').
%%%
%%% One stream per sighting, one event. The stream exists because a sighting is
%%% EVIDENCE: an abuse report to a hosting provider is only as good as the
%%% record behind it, and this record is immutable, timestamped, and signed to
%%% the sentinel that saw it. Reuses message_state (no fold).
-module(threat_aggregate).
-behaviour(evoq_aggregate).

-export([init/1, execute/2, apply/2, state_module/0, stream_id/1]).

-spec state_module() -> module().
state_module() -> message_state.

init(AggregateId) ->
    {ok, message_state:new(AggregateId)}.

-spec stream_id(binary()) -> binary().
stream_id(Id) when is_binary(Id) ->
    <<"sight-", Id/binary>>.

execute(_State, #{command_type := <<"report_threat">>} = Payload) ->
    maybe_report_threat:handle_from_map(Payload);
execute(_State, _Payload) ->
    {error, unknown_command}.

apply(State, _Event) ->
    State.
