%%% @doc State module for the threat (sighting) aggregate.
%%%
%%% A sighting is a one-event stream, recorded once for provenance. There is no
%%% state to fold, so this is deliberately trivial — the aggregate exists only to
%%% turn a warden's report into an immutable, attributable event.
-module(sighting_state).
-behaviour(evoq_state).

-export([new/1, apply_event/2, to_map/1]).

new(_AggregateId) -> #{}.

apply_event(State, _Event) -> State.

to_map(State) -> State.
