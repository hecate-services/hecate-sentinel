%%% @doc State module for the threat (sighting) aggregate.
%%%
%%% A sighting is a one-event stream, recorded once for provenance. The only
%%% state worth folding is whether that one event is already there, which is
%%% what lets threat_aggregate refuse a duplicate delivery of an observation we
%%% already hold. Sighting ids are derived from the observation
%%% (ingest_warden_reports:sighting_id/5), so a redelivery addresses this same
%%% stream rather than minting a new one.
-module(sighting_state).
-behaviour(evoq_state).

-export([new/1, apply_event/2, to_map/1]).

new(_AggregateId) -> #{}.

%% Replayed on aggregate load (evoq_aggregate:load_or_init/3), so this survives
%% the aggregate process being recycled, not just one process lifetime.
apply_event(State, _Event) -> State#{recorded => true}.

to_map(State) -> State.
