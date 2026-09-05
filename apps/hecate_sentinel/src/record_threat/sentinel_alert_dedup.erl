%% @doc Whether a cross-border `spartan/broadcast' alert has already been
%% sent for an attacker IP, surviving restarts.
%%
%% `threat_sighted_v1_to_threats' rebuilds its ENTIRE read model
%% (`hecate_sentinel_threats', an in-memory `evoq_read_model_ets' table)
%% from the full evidence log on every single boot, by design -- that is
%% the whole point of the read model being ephemeral. Wiring evoq's
%% generic per-projection checkpoint onto that projection would gate the
%% WHOLE `project/4' call, including the read-model rebuild itself, so a
%% restart would silently stop repopulating any history older than the
%% last checkpoint -- Vigil would show only attacks since the last
%% restart instead of the whole map. See the module doc on
%% `threat_sighted_v1_to_threats' for the reasoning this ruled out.
%%
%% What actually needs to survive a restart is narrower: has this
%% specific IP already reached the minds once. Tracked here as one
%% snapshot per IP (the same underlying primitive `reckon_evoq_checkpoint_store'
%% uses for per-projection checkpoints, keyed per-attacker instead) so a
%% restart's replay re-detects the SAME historical crossing (the read
%% model has no memory of its own past runs, so it always will) without
%% re-notifying anyone about it. The read model rebuild itself, and the
%% `sentinel/campaign' publish, are both left untouched -- a boot-replay
%% repaint of either is harmless (Vigil folds by IP, non-idempotent-fact
%% concerns don't apply to a map that upserts).
-module(sentinel_alert_dedup).

-export([already_alerted/1, mark_alerted/1]).
-export([snapshot_count/1]). %% test introspection only

-define(STORE_ID, hecate_sentinel_store).

%% @doc True if a broadcast alert has already been recorded for Ip.
-spec already_alerted(binary()) -> boolean().
already_alerted(Ip) ->
    StreamId = stream_id(Ip),
    case reckon_gater_api:list_snapshots(?STORE_ID, StreamId, StreamId) of
        {ok, [_ | _]} -> true;
        {ok, []} -> false;
        {error, _} ->
            %% Fail OPEN (treat as "not yet alerted") rather than closed:
            %% a gateway hiccup here must not suppress a genuinely new
            %% cross-border alert. Worst case on a transient read failure
            %% is one duplicate notification, not a permanently silenced
            %% attacker.
            false
    end.

%% @doc Record that a broadcast alert has now been sent for Ip. Fire and
%% forget, same as evoq's own checkpoint saves (reckon_evoq_checkpoint_store,
%% evoq_projection:save_checkpoint/3) -- a failed write here costs one
%% possible duplicate alert on the next restart, not correctness.
-spec mark_alerted(binary()) -> ok.
mark_alerted(Ip) ->
    StreamId = stream_id(Ip),
    SnapshotRecord = #{
        data => #{alerted => true},
        metadata => #{alerted_at => erlang:system_time(millisecond)},
        timestamp => erlang:system_time(millisecond)
    },
    reckon_gater_api:record_snapshot(?STORE_ID, StreamId, StreamId, 0, SnapshotRecord).

stream_id(Ip) -> <<"sentinel-alerted-", Ip/binary>>.

%% @doc Test-only: exactly how many alert markers are persisted for Ip.
%% Lets a test distinguish "marked once" from "marked twice" -- something
%% `already_alerted/1' alone can't (it only ever reports true/false),
%% which is exactly the distinction a re-notification bug would need
%% catching on.
-spec snapshot_count(binary()) -> non_neg_integer().
snapshot_count(Ip) ->
    StreamId = stream_id(Ip),
    case reckon_gater_api:list_snapshots(?STORE_ID, StreamId, StreamId) of
        {ok, Snapshots} -> length(Snapshots);
        {error, _} -> 0
    end.
