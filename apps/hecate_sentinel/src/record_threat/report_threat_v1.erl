%%% @doc report_threat_v1 command — a sentinel saw someone trying to break in.
%%%
%%% Every public box in this federation is under continuous attack (tens of
%%% thousands of SSH attempts a day, hundreds of distinct hosts). A sentinel
%%% watching one box reports what it sees; the sighting crosses the mesh; the
%%% other countries learn about an attacker BEFORE it reaches them. We measured
%%% the head start on real traffic: a median of 56 minutes between the same
%%% attacker hitting one country and the next.
-module(report_threat_v1).
-behaviour(evoq_command).

-export([new/1, new/9, to_map/1, from_map/1, command_type/0]).

-record(report_threat_v1, {
    sighting_id :: binary(),
    reporter    :: binary() | undefined, %% the warden's ephemeral service DID
    label       :: binary() | undefined, %% stable box name ("helsinki") — the
                                          %% correlation key; DID regenerates on
                                          %% restart, the label does not
    source_ip   :: binary(),
    service     :: binary(),   %% ssh | http | ...
    attempts    :: integer(),  %% in the observation window
    window_s    :: integer(),
    usernames   :: [binary()], %% what they tried (evidence, and it is revealing)
    at          :: integer()
}).

-opaque report_threat_v1() :: #report_threat_v1{}.
-export_type([report_threat_v1/0]).

command_type() -> report_threat.

new(#{sighting_id := I, reporter := R, source_ip := Ip} = M) ->
    {ok, new(I, R,
             maps:get(label, M, undefined),
             Ip,
             maps:get(service, M, <<"ssh">>),
             maps:get(attempts, M, 1),
             maps:get(window_s, M, 60),
             maps:get(usernames, M, []),
             maps:get(at, M, erlang:system_time(millisecond)))};
new(_) ->
    {error, missing_fields}.

new(Id, Reporter, Label, Ip, Service, Attempts, WindowS, Usernames, At) ->
    #report_threat_v1{sighting_id = Id, reporter = Reporter, label = Label,
                      source_ip = Ip, service = Service, attempts = Attempts,
                      window_s = WindowS, usernames = Usernames, at = At}.

-spec to_map(report_threat_v1()) -> map().
to_map(#report_threat_v1{sighting_id = I, reporter = R, label = L, source_ip = Ip,
                         service = S, attempts = A, window_s = W,
                         usernames = U, at = At}) ->
    #{command_type => <<"report_threat">>,
      sighting_id => I, reporter => R, label => L, source_ip => Ip, service => S,
      attempts => A, window_s => W, usernames => U, at => At}.

-spec from_map(map()) -> {ok, report_threat_v1()} | {error, term()}.
from_map(#{sighting_id := I, reporter := R, source_ip := Ip} = M) ->
    new(M#{sighting_id => I, reporter => R, source_ip => Ip});
from_map(_) ->
    {error, invalid_report_threat_command}.
