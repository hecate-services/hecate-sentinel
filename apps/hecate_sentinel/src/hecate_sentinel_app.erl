%%% @doc hecate_sentinel OTP application entry.
-module(hecate_sentinel_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    hecate_om:boot(hecate_sentinel_service).

stop(_State) ->
    ok.
