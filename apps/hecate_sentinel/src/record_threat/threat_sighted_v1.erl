%%% @doc threat_sighted_v1 event — an attacker was seen, and it is now on the
%%% record. This is the evidence chain: immutable, timestamped, attributable to
%%% the sentinel that saw it. It is what an abuse report is built from.
-module(threat_sighted_v1).
-behaviour(evoq_event).

-export([new/1, to_map/1, from_map/1, event_type/0]).

event_type() -> <<"threat_sighted_v1">>.

new(M) when is_map(M) ->
    #{event_type => <<"threat_sighted_v1">>,
      sighting_id => maps:get(sighting_id, M),
      reporter    => maps:get(reporter, M),
      source_ip   => maps:get(source_ip, M),
      service     => maps:get(service, M, <<"ssh">>),
      attempts    => maps:get(attempts, M, 1),
      window_s    => maps:get(window_s, M, 60),
      usernames   => maps:get(usernames, M, []),
      at          => maps:get(at, M, erlang:system_time(millisecond))}.

-spec to_map(map()) -> map().
to_map(M) -> M.

-spec from_map(map()) -> {ok, map()} | {error, term()}.
from_map(#{sighting_id := _, source_ip := _} = M) -> {ok, M};
from_map(_)                                       -> {error, invalid_threat_sighted_event}.
