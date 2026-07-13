%%% @doc Handler for the report_threat command.
-module(maybe_report_threat).

-export([handle/1, handle_from_map/1, dispatch/1]).

-dialyzer({nowarn_function, [dispatch/1]}).

-spec handle_from_map(map()) -> {ok, [map()]} | {error, term()}.
handle_from_map(#{sighting_id := _, reporter := _, source_ip := Ip} = Payload) ->
    validate_and_emit(Ip, Payload);
handle_from_map(_) ->
    {error, missing_fields}.

-spec handle(report_threat_v1:report_threat_v1()) -> {ok, [map()]} | {error, term()}.
handle(Command) ->
    Map = report_threat_v1:to_map(Command),
    validate_and_emit(maps:get(source_ip, Map), Map).

validate_and_emit(Ip, Payload) ->
    case validate(Ip) of
        ok              -> {ok, [threat_sighted_v1:new(Payload)]};
        {error, Reason} -> {error, Reason}
    end.

-spec dispatch(report_threat_v1:report_threat_v1()) ->
    {ok, non_neg_integer(), [map()]} | {error, term()}.
dispatch(Cmd) ->
    #{sighting_id := Id} = CmdMap = report_threat_v1:to_map(Cmd),
    EvoqCmd = evoq_command:new(
        report_threat,
        threat_aggregate,
        threat_aggregate:stream_id(Id),
        CmdMap,
        #{timestamp => erlang:system_time(millisecond)}
    ),
    Opts = #{store_id => hecate_sentinel_store,
             adapter => reckon_evoq_adapter,
             consistency => eventual},
    evoq_command_router:dispatch(EvoqCmd, Opts).

%% An IP, and nothing else. A sentinel that reports garbage poisons the evidence
%% chain every abuse report is built from, so it is rejected at the door.
validate(Ip) when is_binary(Ip), Ip =/= <<>> ->
    case inet:parse_address(binary_to_list(Ip)) of
        {ok, _}    -> ok;
        {error, _} -> {error, not_an_ip}
    end;
validate(_) ->
    {error, source_ip_required}.
