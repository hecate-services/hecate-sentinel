%%% @doc Attacker enrichment — GeoIP + ASN, from the MaxMind databases.
%%%
%%% Every attacker IP is looked up once and decorated with where it is and what
%%% network it belongs to. The network is often more telling than the country: a
%%% RESIDENTIAL ISP means a compromised home device (a botnet foot soldier); a
%%% HOSTING/cloud ASN (OVH, DigitalOcean, a bulletproof host) means a rented or
%%% compromised server built for attacking. That distinction is exactly the kind
%%% of context a mind can reason over and a rule engine cannot.
%%%
%%% The databases are mounted at runtime, never bundled (the MaxMind licence
%%% forbids redistribution). If they are absent, `lookup/1' returns an empty map
%%% and everything else carries on — enrichment is additive, never load-bearing.
-module(hecate_sentinel_enrich).
-behaviour(gen_server).

-export([start_link/0, lookup/1, net_type/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(CITY, geoip_city).
-define(ASN, geoip_asn).

-record(st, {ready = false :: boolean()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Decorate an IP with country/city/ASN/org. Empty map if the databases
%% are not loaded or the IP is not found.
-spec lookup(binary()) -> map().
lookup(Ip) when is_binary(Ip) ->
    geo(safe_lookup(?CITY, Ip), safe_lookup(?ASN, Ip));
lookup(_) ->
    #{}.

init([]) ->
    _ = load(?CITY, application:get_env(hecate_sentinel, geoip_city_db, undefined)),
    _ = load(?ASN, application:get_env(hecate_sentinel, geoip_asn_db, undefined)),
    {ok, #st{}}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.
handle_info(_Info, St)       -> {noreply, St}.
terminate(_Reason, _St)      -> ok.

%% --- Internal ---

load(_Id, undefined) ->
    ok;
load(Id, Path) ->
    load_if(filelib:is_regular(Path), Id, Path).

load_if(false, Id, Path) ->
    logger:warning("[sentinel] geoip ~p not found at ~s — enrichment off", [Id, Path]),
    ok;
load_if(true, Id, Path) ->
    started(catch locus:start_loader(Id, Path), Id).

%% locus:start_loader/2 returns the atom `ok' (not `{ok, Pid}'). Await the load
%% HERE, synchronously in init, so the databases are ready before the read model
%% rebuilds against us at boot — otherwise the rebuild races the async load and
%% records empty geo for every replayed attacker.
started(ok, Id)      -> await(Id);
started({ok, _}, Id) -> await(Id);
started(Other, Id) ->
    logger:warning("[sentinel] geoip ~p loader: ~p", [Id, Other]),
    ok.

await(Id) ->
    _ = locus:await_loader(Id, 15000),
    logger:info("[sentinel] geoip ~p loaded", [Id]),
    ok.

safe_lookup(Id, Ip) ->
    case catch locus:lookup(Id, binary_to_list(Ip)) of
        {ok, Entry} when is_map(Entry) -> Entry;
        _                              -> #{}
    end.

%% Flatten the two MaxMind entries into a small, flat map of what we care about.
geo(City, Asn) ->
    Org = path(Asn, [<<"autonomous_system_organization">>]),
    prune(#{
        country_iso => path(City, [<<"country">>, <<"iso_code">>]),
        country     => path(City, [<<"country">>, <<"names">>, <<"en">>]),
        city        => path(City, [<<"city">>, <<"names">>, <<"en">>]),
        lat         => path(City, [<<"location">>, <<"latitude">>]),
        lng         => path(City, [<<"location">>, <<"longitude">>]),
        asn         => path(Asn, [<<"autonomous_system_number">>]),
        asn_org     => Org,
        net_type    => net_type(Org)
    }).

%% Best-effort classification from the ASN org name. A hosting/cloud ASN is a
%% rented or compromised SERVER built to attack; an ISP/telecom ASN is more
%% likely a compromised home device (a botnet foot soldier). This is the single
%% distinction a mind can reason over that a rule engine cannot. It is a
%% heuristic on the org string, not a MaxMind field: the free GeoLite2 DB has no
%% connection type, so `unknown' is honest, not a bug.
net_type(Org) when is_binary(Org) -> classify(string:lowercase(Org));
net_type(_)                       -> undefined.

classify(L) ->
    class(contains_any(L, hosting_terms()), contains_any(L, isp_terms())).

class(true, _)      -> hosting;
class(false, true)  -> isp;
class(false, false) -> unknown.

contains_any(L, Terms) ->
    lists:any(fun(T) -> string:find(L, T) =/= nomatch end, Terms).

hosting_terms() ->
    ["host", "cloud", "server", "datacenter", "data center", "colo", "vps",
     "ovh", "digitalocean", "amazon", "aws", "google", "azure", "microsoft",
     "alibaba", "hetzner", "linode", "vultr", "contabo", "leaseweb", "m247",
     "choopa", "unmanaged", "bulletproof", "technolog"].

isp_terms() ->
    ["telecom", "communication", "broadband", "cable", "mobile", "wireless",
     "telefonica", "vodafone", "airtel", "comcast", "orange", "telekom", "isp",
     "internet servic", "dsl", "fiber", "viettel", "mobifone", "uzbektelekom"].

path(Map, Keys) ->
    lists:foldl(fun(_K, undefined) -> undefined;
                   (K, M) when is_map(M) -> maps:get(K, M, undefined);
                   (_K, _) -> undefined
                end, Map, Keys).

prune(M) ->
    maps:filter(fun(_K, V) -> V =/= undefined end, M).
