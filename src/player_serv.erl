-module(player_serv).
-export([start_link/15, stop/1]).
-export([become_source/3,
         become_target/2,
         become_forwarder/2,
         become_nothing/1]).
-export([buffer_read/2,
         buffer_write/3,
         buffer_size/1,
         buffer_select_suitable/3]).
-export([got_message/5]).
-export([pick_as_source/1]).
-export([send_message/3]).
-export([pin_location/2, get_routing_info/1]).
-export([start_location_updating/1]).
-export([message_handler/1]).
-export_type([message_id/0, pick_mode/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include("../include/player_serv.hrl").
-include("../include/player_sync_serv.hrl").
-include("../include/player_buffer.hrl").
-include("player_routing.hrl").

-define(KEYDIR_PUSHBACK_TIME, 10000).
-define(KEYDIR_NETWORK_TIMEOUT, 20000).

-define(STORED_MESSAGE_DIGESTS, 10000).

-type message_id() :: binary().
-type pick_mode() :: {is_source, {binary(), message_id()}} |
                     {is_target, message_id()} |
                     {is_forwarder,
                      {message_not_in_buffer |
                       message_in_buffer, message_id()}} |
                     is_nothing.
-type keydir_mode() ::
        local |
        {service, keydir_service:password(), keydir_service:access()}.

-record(state,
        {parent :: pid(),
         nym :: binary(),
         maildrop_serv_pid = not_set :: pid() | not_set,
         keydir_serv_pid = not_set :: pid() | not_set,
         sync_address :: {inet:ip_address(), inet:port_number()},
         buffer_size :: integer(),
         f :: number(),
         k :: number(),
         temp_dir :: binary(),
         buffer_dir :: binary(),
         buffer_handle :: player_buffer:buffer_handle(),
         message_digests :: atom(),
         keys :: {#pk{}, #sk{}},
         reply_keys = not_set :: {#pk{}, #sk{}} | not_set,
         simulated_longitude_topic :: binary() | not_set,
         simulated_latitude_topic :: binary() | not_set,
         location_generator :: function(),
         use_gps :: boolean(),
         longitude = none :: float() | none,
         latitude = none :: float() | none,
         routing_info :: #routing_info{},
         neighbour_state = #{} ::
           #{nodis:addr() => nodis:state() },
	 neighbour_mon = #{} ::
           #{nodis:addr() => undefined | pid(),
	     reference() => {nodis:addr(), pid()}},
         is_zombie = false :: boolean(),
         picked_as_source = false :: boolean(),
         pick_mode = is_nothing :: pick_mode(),
         meters_moved = 0 :: integer(),
         keydir_mode :: keydir_mode(),
         simulated :: boolean(),
	 nodis_serv_pid :: pid() | undefined,
         nodis_subscription :: reference() | undefined,
         reserved_message_indices = [] ::
           [{pid(), Index :: pos_integer()}],
         is_pinned_by_simulator = false :: boolean()}).

%%
%% Exported: start_link
%%

-spec start_link(binary(), {inet:ip_address(), inet:port_number()}, integer(),
                 number(), number(), binary(), binary(),
                 player_routing:routing_type(), boolean(), float(), float(),
                 {#pk{}, #sk{}}, function() | not_set, keydir_mode(),
                 boolean()) ->
          serv:spawn_server_result().

start_link(Nym, SyncAddress, BufferSize, F, K, TempDir, BufferDir, RoutingType,
           UseGps, Longitude, Latitude, Keys, GetLocationGenerator, KeydirMode,
           Simulated) ->
    ?spawn_server(
       fun(Parent) ->
               init(Parent, Nym, SyncAddress, BufferSize, F, K, TempDir,
                    BufferDir, RoutingType, UseGps, Longitude, Latitude, Keys,
                    GetLocationGenerator, KeydirMode, Simulated)
       end,
       fun initial_message_handler/1).

initial_message_handler(#state{nym = Nym,
                               keys = {Pk, _Sk},
                               keydir_mode = KeydirMode,
                               simulated = Simulated} = State) ->
    receive
        {neighbour_workers, NeighbourWorkers} ->
            case Simulated of
                true ->
                    [MaildropServPid, NodisServPid, KeydirServPid] =
                        supervisor_helper:get_selected_worker_pids(
                          [maildrop_serv, nodis_serv, keydir_serv],
                          NeighbourWorkers);
                false->
                    [MaildropServPid, KeydirServPid] =
                        supervisor_helper:get_selected_worker_pids(
                          [maildrop_serv, keydir_serv],
                          NeighbourWorkers),
                    NodisServPid = whereis(nodis_serv)
            end,
            {ok, NodisSubscription} = nodis_serv:subscribe(NodisServPid),
            ok = publish_public_key(KeydirServPid, KeydirMode, Nym, Pk),
            {swap_message_handler, fun ?MODULE:message_handler/1,
             State#state{maildrop_serv_pid = MaildropServPid,
                         keydir_serv_pid = KeydirServPid,
			 nodis_serv_pid = NodisServPid,
                         nodis_subscription = NodisSubscription}}
    end.

%%
%% Exported: stop
%%

-spec stop(pid()) -> ok.

stop(Pid) ->
    serv:call(Pid, stop).

%%
%% Exported: pin_location
%%

-spec pin_location(pid(), {number(), number()}) -> ok.

pin_location(Pid, {Longitude, Latitude}) ->
    serv:cast(Pid, {pin_location, Longitude, Latitude}).

%%
%% Exported: become_source
%%

-spec become_source(pid(), binary(), message_id()) -> ok.

become_source(Pid, TargetNym, MessageMD5) ->
    serv:cast(Pid, {become_source, TargetNym, MessageMD5}).

%%
%% Exported: become_target
%%
-spec become_target(pid(), message_id()) ->
          ok.

become_target(Pid, MessageMD5) ->
    serv:cast(Pid, {become_target, MessageMD5}).

%%
%% Exported: become_forwarder
%%

-spec become_forwarder(pid(), message_id()) -> ok.

become_forwarder(Pid, MessageMD5) ->
    serv:cast(Pid, {become_forwarder, MessageMD5}).

%%
%% Exported: become_nothing
%%

-spec become_nothing(pid()) -> ok.

become_nothing(Pid) ->
    serv:cast(Pid, become_nothing).

%%
%% Exported: buffer_read
%%

-spec buffer_read(Pid::pid(), Index::non_neg_integer()) ->
	  {ok, Message::binary()}.

buffer_read(Pid, Index) ->
    serv:call(Pid, {buffer_read, Index}).

%%
%% Exported: buffer_write
%%

-spec buffer_write(Pid::pid(), Index::non_neg_integer(),
		   Message::binary()) ->
	  ok.

buffer_write(Pid, Index, Message) ->
    serv:call(Pid, {buffer_write, Index, Message}).

%%
%% Exported: buffer_size
%%

-spec buffer_size(pid()) -> integer().

buffer_size(Pid) ->
    serv:call(Pid, buffer_size).

%%
%% Exported: buffer_select_suitable
%%

-spec buffer_select_suitable(pid(), #routing_info{}, Factor::float()) ->
          [integer()].

buffer_select_suitable(Pid, NeighbourRoutingInfo, F) ->
    serv:call(Pid, {buffer_select_suitable, NeighbourRoutingInfo, F}).

%%
%% Exported: got_message
%%

-spec got_message(
        pid(), message_id(), binary(), non_neg_integer(), binary()) ->
          ok.

got_message(Pid, Message, SenderNym, Signature, DecryptedData) ->
    serv:cast(Pid, {got_message, Message, SenderNym, Signature,
                    DecryptedData}).

%%
%% Exported: pick_as_source
%%

-spec pick_as_source(pid()) -> ok.

pick_as_source(Pid) ->
    serv:cast(Pid, pick_as_source).

%%
%% Exported: send_message
%%

-spec send_message(pid(), binary(), binary()) ->
          ok | {error, any()}.

send_message(Pid, RecipientNym, Payload) ->
    serv:call(Pid, {send_message, RecipientNym, Payload}).

%%
%% Exported: start_location_updating
%%

-spec start_location_updating(pid()) -> ok.

start_location_updating(Pid) ->
    serv:cast(Pid, start_location_updating).

%%
%% Exported: get_routing_info
%%

-spec get_routing_info(pid()) -> #routing_info{}.

get_routing_info(Pid) ->
    serv:call(Pid, get_routing_info).

%%
%% Server
%%

init(Parent, Nym, SyncAddress, BufferSize, F, K, TempDir, BufferDir,
     RoutingType, UseGps, Longitude, Latitude, Keys, GetLocationGenerator,
     KeydirMode, Simulated) ->
    rand:seed(exsss),
    {ok, BufferHandle} = player_buffer:new(BufferDir, BufferSize, Simulated),
    case Simulated of
        true ->
            TopicPrefix =
                ?l2b([<<"mixmesh.routing.simulated.">>, Nym, <<".location">>]),
            SimulatedLongitudeTopic = ?l2b([TopicPrefix, <<".longitude">>]),
            SimulatedLatitudeTopic = ?l2b([TopicPrefix, <<".latitude">>]),
            true = xbus:pub_meta(SimulatedLongitudeTopic, [{unit, "degree"}]),
            true = xbus:pub_meta(SimulatedLatitudeTopic, [{unit, "degree"}]),
            LocationGenerator = GetLocationGenerator();
        false ->
            SimulatedLongitudeTopic = not_set,
            SimulatedLatitudeTopic = not_set,
            LocationGenerator = not_set
    end,
    ok = config_serv:subscribe(),
    MessageDigestsFilename = filename:join([BufferDir, <<"digests.db">>]),
    {ok, MessageDigests} =
        persistent_circular_buffer:open(
          {digests, Nym}, ?b2l(MessageDigestsFilename),
          ?STORED_MESSAGE_DIGESTS),
    ?daemon_log_tag_fmt(
       system, "Player server for ~s has been started", [Nym]),
    {ok, #state{parent = Parent,
                nym = Nym,
                sync_address = SyncAddress,
                buffer_size = BufferSize,
                f = F,
                k = K,
                temp_dir = TempDir,
                buffer_dir = BufferDir,
                buffer_handle = BufferHandle,
                message_digests = MessageDigests,
                keys = Keys,
                simulated_longitude_topic = SimulatedLongitudeTopic,
                simulated_latitude_topic = SimulatedLatitudeTopic,
                location_generator = LocationGenerator,
                use_gps = UseGps,
                longitude = Longitude,
                latitude = Latitude,
                routing_info = #routing_info{type = RoutingType},
                keydir_mode = KeydirMode,
                simulated = Simulated}}.

message_handler(
  #state{parent = Parent,
         nym = Nym,
         maildrop_serv_pid = MaildropServPid,
         keydir_serv_pid = KeydirServPid,
         sync_address = SyncAddress,
         buffer_size = _BufferSize,
         f = F,
         k = K,
         temp_dir = TempDir,
         buffer_dir = _BufferDir,
         buffer_handle = BufferHandle,
         message_digests = MessageDigests,
         keys = {_Pk, Sk} = Keys,
         simulated_longitude_topic = SimulatedLongitudeTopic,
         simulated_latitude_topic = SimulatedLatitudeTopic,
         location_generator = LocationGenerator,
         use_gps = _UseGps,
         longitude = Longitude,
         latitude = Latitude,
         routing_info = RoutingInfo,
         neighbour_state = NeighbourState,
	 neighbour_mon = NeighbourMon,
         is_zombie = IsZombie,
         picked_as_source = _PickedAsSource,
         pick_mode = PickMode,
         meters_moved = MetersMoved,
         keydir_mode = KeydirMode,
         simulated = Simulated,
	 nodis_serv_pid = NodisServPid,
         nodis_subscription = NodisSubscription,
         is_pinned_by_simulator = IsPinnedBySimulator} = State) ->
    receive
        config_updated ->
            ?daemon_log_tag_fmt(system, "Player noticed a config change", []),
            noreply;
        {call, From, stop} ->
            {stop, From, ok};
        {cast, {become_source, TargetNym, MessageMD5}} ->
	    ?dbg_log_fmt("~s has been elected as new source (~s)",
                         [Nym, ?bin2xx(MessageMD5)]),
            Count = count_messages(MessageMD5, BufferHandle),
            NewPickMode = {is_source, {TargetNym, MessageMD5}},
            true = player_db:update(
                     #db_player{nym = Nym,
                                count = Count,
                                pick_mode = NewPickMode}),
            {noreply, State#state{pick_mode = NewPickMode}};
        {cast, {become_target, MessageMD5}} ->
	    ?dbg_log_fmt("~s has been elected as new target (~s)",
                         [Nym, ?bin2xx(MessageMD5)]),
            NewPickMode = {is_target, MessageMD5},
            Count = count_messages(MessageMD5, BufferHandle),
            true = player_db:update(
                     #db_player{nym = Nym,
                                count = Count,
                                pick_mode = NewPickMode}),
            {noreply, State#state{pick_mode = NewPickMode}};
        {cast, {become_forwarder, MessageMD5}} ->
	    ?dbg_log_fmt("~s has been elected as forwarder (~s)",
			 [Nym, ?bin2xx(MessageMD5)]),
            NewPickMode = {is_forwarder, {message_not_in_buffer, MessageMD5}},
            Count = count_messages(MessageMD5, BufferHandle),
            true = player_db:update(
                     #db_player{nym = Nym,
                                count = Count,
                                pick_mode = NewPickMode}),
	    {noreply, State#state{pick_mode = NewPickMode}};
        {cast, become_nothing} ->
            NewPickMode = is_nothing,
            true = player_db:update(
                     #db_player{nym = Nym,
                                count = 0,
                                pick_mode = NewPickMode}),
	    {noreply, State#state{pick_mode = NewPickMode}};
        {call, From, {buffer_read, Index}} ->
	    Message = player_buffer:read(BufferHandle, Index),
	    {reply, From, {ok, Message}, State};
        {call, From, {buffer_write, Index, RoutingHeaderAndMessage}} ->
	    ok = player_buffer:write(
                   BufferHandle, Index, RoutingHeaderAndMessage),
	    if
                Simulated ->
		    TracedMessageMD5 = traced_message(),
		    Count = count_messages(TracedMessageMD5, BufferHandle),
		    IsForwarder =
                        case PickMode of
                            {is_forwarder, {_, TracedMessageMD5}} ->
                                true;
                            _ ->
                                false
                        end,
		    NewPickMode =
			if IsForwarder, Count =:= 0 ->
				%% message overwritten or never in buffer
				{is_forwarder,
                                 {message_not_in_buffer, TracedMessageMD5}};
			   IsForwarder, Count > 0 ->
				{is_forwarder,
                                 {message_in_buffer, TracedMessageMD5}};
			   true ->
				PickMode  %% keep previous mode
			end,
		    true = player_db:update(
			     #db_player{
				nym = Nym,
				count = Count,
				buffer_size =
				    player_buffer:size(BufferHandle),
				pick_mode = NewPickMode}),
		    {reply, From, ok, State#state{pick_mode = NewPickMode}};
                true ->
		    {reply, From, ok, State}
	    end;
        {call, From, buffer_size} ->
	    {reply, From, player_buffer:size(BufferHandle)};
        {call, From, {buffer_select_suitable, NeighbourRoutingInfo, F}} ->
	    {reply, From,
             player_buffer:select_suitable(
               BufferHandle, RoutingInfo, NeighbourRoutingInfo, F)};
        {cast, {got_message, _, _, _, _}} when IsZombie ->
            noreply;
        {cast, {got_message, Message, SenderNym, Signature, DecryptedData}} ->
	    MessageMD5 = erlang:md5(Message),
            DigestedDecryptedData = erlang:md5(DecryptedData),
            case persistent_circular_buffer:exists(
                   MessageDigests, DigestedDecryptedData) of
                false ->
                    Verified =
			case read_public_key(KeydirServPid, KeydirMode,
                                             SenderNym) of
			    {ok, SenderPk} ->
                                elgamal:verify(Signature, DecryptedData,
                                               SenderPk);
                            {error, Reason} ->
                                ?dbg_log({public_key_not_available, Reason}),
				false
			end,
                    TempFilename = mail_util:mktemp(TempDir),
                    Mail = DecryptedData,
                    case Verified of
                        true ->
                            ?daemon_log_fmt(
                               "~s received a verified message from ~s (~s)",
                               [Nym, SenderNym, ?bin2xx(MessageMD5)]),
                            Footer = <<"\n\nNOTE: This mail is verified">>,
                            MailWithFooter =
                                mail_util:inject_footer(Mail, Footer),
                            ok = file:write_file(TempFilename, MailWithFooter);
                        false ->
                            ?daemon_log_fmt(
                               "~s received an *unverified* message from ~s (~s)",
                               [Nym, SenderNym, ?bin2xx(MessageMD5)]),
                            MailWithExtraHeaders =
                                mail_util:inject_headers(
                                  Mail, [{<<"MT-Priority">>, <<"9">>},
                                         {<<"X-Priority">>, <<"1">>}]),
                            Footer =
                                <<"\n\nWARNING: This mail is *not* verified">>,
                            MailWithFooter =
                                mail_util:inject_footer(
                                  MailWithExtraHeaders, Footer),
                            ok = file:write_file(TempFilename, MailWithFooter)
                    end,
                    {ok, _} =
                        maildrop_serv:write(MaildropServPid, TempFilename),
                    ok = file:delete(TempFilename),
                    case Simulated of
                        true ->
                            case PickMode of
                                {is_target, MessageMD5} ->
                                    ?dbg_log_fmt(
                                       "~w target received message (~s)",
                                       [Nym, ?bin2xx(MessageMD5)]),
                                    true = ets:delete(
                                             player_message, MessageMD5),
                                    ok = simulator_serv:target_received_message(
                                           Nym, SenderNym);
                                _ ->
                                    ok = simulator_serv:received_message(
                                           Nym, SenderNym)
                            end,
                            true = stats_db:message_received(
                                     MessageMD5, SenderNym, Nym);
                        false ->
                            ok
                    end,
                    ok = persistent_circular_buffer:add(
                           MessageDigests, DigestedDecryptedData),
                    {noreply, State};
                true ->
                    ?daemon_log_fmt(
                       "~s received a duplicated message from ~s (~s)",
                       [Nym, SenderNym, ?bin2xx(MessageMD5)]),
                    case Simulated of
                        true ->
                            stats_db:message_duplicate_received(
                              DigestedDecryptedData, SenderNym, Nym);
                        false ->
                            true
                    end,
                    noreply
            end;
        {cast, pick_as_source} ->
            {noreply, State#state{picked_as_source = true}};
        {call, From, {send_message, RecipientNym, Payload}} ->
            case read_public_key(KeydirServPid, KeydirMode, RecipientNym) of
                {ok, RecipientPk} ->
                    EncryptedData =
                        elgamal:uencrypt(Payload, RecipientPk, Sk),
		    IndexList = player_buffer:select(BufferHandle, K),
		    MessageMD5 = erlang:md5(EncryptedData),
                    RecipientRoutingHeader =
                        case Simulated of
                            true ->
                                #{routing_info := RecipientRoutingInfo} =
                                    player_info:get(RecipientNym),
                                player_routing:info_to_header(
                                  RecipientRoutingInfo);
                            false ->
                                player_routing:info_to_header(blind)
                        end,
                    ok = write_messages(BufferHandle, RecipientRoutingHeader,
                                        EncryptedData, IndexList),
                    case Simulated of
                        true ->
                            true = stats_db:message_created(
                                     MessageMD5, Nym, RecipientNym),
                            ok = simulator_serv:elect_source_and_target(
                                   MessageMD5, Nym, RecipientNym),
                            {reply, From, ok, State};
                        false ->
                            {reply, From, ok, State}
                    end;
                {error, Reason} ->
                    {reply, From, {error, Reason}}
            end;
        {cast, start_location_updating} ->
            true = player_db:add(Nym, Longitude, Latitude),
            true = player_db:update(
                     #db_player{
                        nym = Nym,
                        buffer_size = player_buffer:size(BufferHandle)}),
            self() ! {location_updated, 0},
            noreply;
        {call, From, get_routing_info} ->
	    {reply, From, RoutingInfo, State};
        {cast, {pin_location, NewLongitude, NewLatitude}} ->
            true = player_db:update(
                     #db_player{nym = Nym,
                                x = NewLongitude,
                                y = NewLatitude,
                                buffer_size =
                                    player_buffer:size(BufferHandle)}),
            UpdatedRoutingInfo =
                player_routing:update_info(
                  RoutingInfo, NewLongitude, NewLatitude),
            true = player_info:set(Nym, routing_info, UpdatedRoutingInfo),
            {noreply, State#state{longitude = NewLongitude,
                                  latitude = NewLatitude,
                                  routing_info = UpdatedRoutingInfo,
                                  is_pinned_by_simulator = true}};
        %%
        %% Nodis subscription events
        %%
        {nodis, NodisSubscription, {pending, NAddr}} ->
            ?dbg_log_tag(nodis, {pending, NAddr}),
            NeighbourState1 = NeighbourState#{ NAddr => pending },
            update_neighbours(Simulated, Nym, NeighbourState1),
            {noreply, State#state{neighbour_state=NeighbourState }};
        {nodis, NodisSubscription, {up, NAddr}} ->
            ?dbg_log_tag(nodis, {up, NAddr}),
            case maps:get(NAddr, NeighbourMon, undefined) of
                undefined ->
                    player_sync_serv:connect(
                      Simulated, self(), NodisServPid, NAddr,
		      #player_sync_serv_options{
			 simulated = Simulated,
			 sync_address = SyncAddress,
			 f = F,
			 keys = Keys}),
		    %% put in pid here? now in {sync,..}
		    {noreply, State};
                Pid when is_pid(Pid) ->
                    ?dbg_log_tag(nodis, {up_already, NAddr}),
		    %% Strange got up when up already in a connection, ignore
                    {noreply, State}
            end;
        {nodis, NodisSubscription, {down,NAddr}} ->
            ?dbg_log_tag(nodis, {down, NAddr}),
            NeighbourState1 = NeighbourState#{ NAddr => down },
            update_neighbours(Simulated, Nym, NeighbourState1),
            case maps:get(NAddr, NeighbourMon, undefined) of
                Pid when is_pid(Pid) ->
		    %% let sync_server get a chance to terminate?
                    %% io:format("Kill sync server ~p\n", [Pid]),
                    %% exit(Pid, softkill),
                    {noreply, State#state{neighbour_state=NeighbourState1}};
                _ ->
                    {noreply, State#state{neighbour_state=NeighbourState1}}
            end;
        {nodis, NodisSubscription, {wait,NAddr}} ->
	    %% neighbour entering wait state (like down)
            ?dbg_log_tag(nodis, {wait, NAddr}),
            NeighbourState1 = NeighbourState#{ NAddr => wait },
            update_neighbours(Simulated, Nym, NeighbourState1),
	    {noreply, State#state{neighbour_state=NeighbourState1}};
	%% player sync messages
	{sync, SyncPid, NAddr, {up, ConState}} -> %% from sync_serv
            ?dbg_log_tag(sync, {up, NAddr, ConState}),
	    Mon = erlang:monitor(process, SyncPid),
	    NeighbourState1 = NeighbourState#{NAddr => {up, ConState}},
	    update_neighbours(Simulated, Nym, NeighbourState1),
	    NeighbourMon1 = NeighbourMon#{Mon => {NAddr, SyncPid},
                                          NAddr => SyncPid},
	    {noreply, State#state{neighbour_state = NeighbourState1,
				  neighbour_mon = NeighbourMon1}};
	{sync, _SyncPid, NAddr, {error, N, _Error}} ->
	    ?dbg_log_tag(sync, {error, N, NAddr, _Error}),
	    %% keep statistics on N messages
	    {noreply, State};
        %% from sync_serv (transmission done)
	{sync, _SyncPid, NAddr, {done, N}} ->
	    ?dbg_log_tag(sync, {done, N, NAddr}),
	    %% keep statistics on N messages
	    {noreply, State};
        {'EXIT', Parent, Reason} ->
            ok = persistent_circular_buffer:close(MessageDigests),
            ok = player_buffer:delete(BufferHandle),
            exit(Reason);
        {'DOWN', Mon, process, SyncPid, Reason} ->
	    %% SyncMon normal close or failure
	    if  Reason =:= normal -> ok;
		Reason =:= killed -> ok;  %% we killed the sync pid
		true ->
                    io:format("sync? process ~w down reason=~p\n", 
			      [SyncPid, Reason])
	    end,
            NeighbourMon1 = 
		case maps:get(Mon, NeighbourMon, undefined) of
		    undefined ->
			io:format("DOWN: sync? process ~w not found\n", 
				  [SyncPid]),
			NeighbourMon;
		    {NAddr, SyncPid} ->
			NMon1 = maps:remove(Mon, NeighbourMon),
			NMon2 = maps:remove(NAddr, NMon1),
			NMon2
		end,
	    {noreply, State#state{neighbour_mon = NeighbourMon1}};
        %%
        %% Below follows handling of internally generated messages
        %%
        {location_updated, _Timestamp} when IsPinnedBySimulator ->
            noreply;
        {location_updated, Timestamp} ->
            case LocationGenerator() of
                end_of_locations ->
                    case Simulated of
                        true ->
                            true = player_db:update(
                                     #db_player{nym = Nym, is_zombie = true});
                        false ->
                            true
                    end,
                    {noreply, State#state{is_zombie = true}};
                {{NextTimestamp, NextLongitude, NextLatitude},
                 NewLocationGenerator} ->
                    ?dbg_log_tag(
                       location, {location_updated, Nym, Longitude, Latitude,
                                  Timestamp, NextLongitude, NextLatitude}),
                    case Simulated of
                        true ->
                            true = player_db:update(
                                     #db_player{
                                        nym = Nym,
                                        x = NextLongitude,
                                        y = NextLatitude}),
                            true = xbus:pub(
                                     SimulatedLongitudeTopic, NextLongitude),
                            true = xbus:pub(
                                     SimulatedLatitudeTopic, NextLatitude);
                        false ->
                            true
                    end,
                    ?dbg_log_tag(location,
				 {will_check_location, Nym,
				  NextTimestamp - Timestamp}),
                    NextUpdate = trunc((NextTimestamp - Timestamp) * 1000),
                    erlang:send_after(NextUpdate, self(),
                                      {location_updated, NextTimestamp}),
                    UpdatedRoutingInfo =
                        player_routing:update_info(
                          RoutingInfo, Longitude, Latitude),
                    case Simulated of
                        true ->
                            true = player_info:set(
                                     Nym, routing_info, UpdatedRoutingInfo);
                        false ->
                            true
                    end,
                    {noreply,
                     State#state{location_generator = NewLocationGenerator,
                                 longitude = NextLongitude,
                                 latitude = NextLatitude,
                                 routing_info = UpdatedRoutingInfo,
                                 meters_moved = MetersMoved}}
            end;
        {system, From, Request} ->
            {system, From, Request};
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

%% Write multiple copies of Message, player_buffer:write will scramble
%% when needed.
write_messages(_BufferHandle, _RoutingHeader, _Message, []) ->
    ok;
write_messages(BufferHandle, RoutingHeader, Message, [Index|IndexList]) ->
    ok = player_buffer:write(BufferHandle, Index, RoutingHeader, Message),
    write_messages(BufferHandle, RoutingHeader, Message, IndexList).

traced_message() ->
    case ets:first(player_message) of
	'$end_of_table' ->  false;
	MessageMD5 -> MessageMD5
    end.

count_messages(false, _BufferHandle) ->
    0;
count_messages(MessageMD5, BufferHandle) ->
    player_buffer:count(BufferHandle, MessageMD5).

update_neighbours(true, Nym, Ns) ->
    true = player_db:update(
	     #db_player{nym = Nym,
			neighbours = get_neighbours(Ns)});
update_neighbours(false, _Nym, _Ns) ->
    true.

-spec get_neighbours(#{nodis:addr() => nodis:state() |
                       {up, connect|accept|false}}) ->
	  [{string(), nodis:state(), connect | accept | false}].

%% FIXME: keep nodis-address -> nym in a global state for speed
get_neighbours(Ns) when is_map(Ns) ->
    get_neighbours_(maps:to_list(Ns), [], []).

get_neighbours_([N|Ns], AddrList, States) ->
    case N of
	{Addr,{up,ConState}} ->
	    get_neighbours_(Ns, [Addr|AddrList], [{Addr, up, ConState}|States]);
	{Addr,up} -> %% FIXME may be removed?
	    get_neighbours_(Ns, [Addr|AddrList], [{Addr, up, false}|States]);
	{Addr,down} ->
	    get_neighbours_(Ns, [Addr|AddrList], [{Addr, down, false}|States]);
	{Addr,pending} ->
	    get_neighbours_(Ns, [Addr|AddrList],
                            [{Addr, pending, false}|States]);
	{Addr,wait} ->
	    get_neighbours_(Ns, [Addr|AddrList], [{Addr, wait, false}|States])
    end;
get_neighbours_([], AddrList, States) ->
    Nyms = simulator_serv:get_player_nyms(AddrList),
    res_neighbours(Nyms, AddrList, States, []).

res_neighbours([Nym|Nyms], [Addr|AddrList],
	       [{Addr, State, ConState}|States],Acc) ->
    res_neighbours(Nyms, AddrList, States, [{Nym, State, ConState}|Acc]);
res_neighbours([], [], [], Acc) ->
    Acc.

%%
%% Keydir access functions
%%

read_public_key(KeydirServPid, local, Nym) ->
    local_keydir_serv:read(KeydirServPid, Nym);
read_public_key(_KeydirServPid, {service, _Password, Access}, Nym) ->
    keydir_service_client:read(Access, {nym, Nym}).

publish_public_key(KeydirServPid, local, Nym, Pk) ->
    case local_keydir_serv:read(KeydirServPid, Nym) of
        {ok, Pk} ->
            ?daemon_log_tag_fmt(system, "Local Keydir server is in sync", []),
            ok;
        {ok, NewPk} ->
            ok = local_keydir_serv:update(KeydirServPid, NewPk),
            ?daemon_log_tag_fmt(system, "Updated the local Keydir server", []),
            ok;
        {error, no_such_key} ->
            ok = local_keydir_serv:create(KeydirServPid, Pk),
            ?daemon_log_tag_fmt(
               system, "Created an entry in the local Keydir server", []),
            ok
    end;
publish_public_key(_KeydirServPid, {service, Password, Access}, _Nym, Pk) ->
    keydir_service_client:publish(Access, Password, Pk).
