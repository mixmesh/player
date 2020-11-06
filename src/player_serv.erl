-module(player_serv).
-export([start_link/9, stop/1]).
-export([pause/1, resume/1]).
-export([become_forwarder/2, become_nothing/1, become_source/3,
         become_target/2]).
-export([buffer_read/2, buffer_write/3, buffer_size/1, buffer_select/2]).
-export([buffer_scramble/2]).
-export([got_message/5]).
-export([pick_as_source/1]).
-export([send_message/4]).
-export([start_location_updating/1]).
-export([get_unique_id/0]).
-export_type([message_id/0, pick_mode/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include_lib("pki/include/pki_serv.hrl").
-include_lib("pki/include/pki_network_client.hrl").
-include("../include/player_serv.hrl").
-include("../include/player_sync_serv.hrl").
-include("../include/player_buffer.hrl").

-define(PKI_PUSHBACK_TIME, 10000).
-define(PKI_NETWORK_TIMEOUT, 20000).

%% -define(DSYNC(F,A), io:format((F),(A))).
-define(DSYNC(F,A), ok).
-define(STORED_MESSAGE_DIGESTS, 10000).

-type message_id() :: pos_integer().
-type pick_mode() :: is_nothing |
                     {is_forwarder,
                      {message_not_in_buffer |
                       message_in_buffer, message_id()}} |
                     {is_source, {TargetNym :: binary(), message_id()}} |
                     {is_target, message_id()}.
-type pki_mode() :: local | {global, binary(), pki_network_client:pki_access()}.

-record(state,
        {parent :: pid(),
         nym :: binary(),
         maildrop_serv_pid = not_set :: pid() | not_set,
         pki_serv_pid = not_set :: pid() | not_set,
         sync_address :: {inet:ip_address(), inet:port_number()},
         temp_dir :: binary(),
         buffer_dir :: binary(),
         buffer_handle :: player_buffer:buffer_handle(),
         message_digests :: atom(),
         keys :: {#pk{}, #sk{}},
         reply_keys = not_set :: {#pk{}, #sk{}} | not_set,
         location_generator :: function(),
         degrees_to_meters :: function(),
         x = none :: integer() | none,
         y = none :: integer() | none,
         neighbour_state = #{} ::
           #{nodis:node_address() => nodis:node_state() },
	 neighbour_pid = #{} ::
           #{nodis:address() => undefined | pid(),
             pid() => nodis:node_address() },
         is_zombie = false :: boolean(),
         picked_as_source = false :: boolean(),
         pick_mode = is_nothing :: pick_mode(),
         paused = false :: boolean(),
         meters_moved = 0 :: integer(),
         pki_mode :: pki_mode(),
         simulated :: boolean(),
	 nodis_serv_pid :: pid() | undefined,
         nodis_subscription :: reference() | undefined,
         reserved_message_indices = [] ::
           [{pid(), Index :: pos_integer()}]}).

%% Exported: start_link

-spec start_link(binary(), {inet:ip_address(), inet:port_number()}, binary(),
                 binary(), {#pk{}, #sk{}}, function(), function(), pki_mode(),
                 boolean()) ->
          serv:spawn_server_result().

start_link(Nym, SyncAddress, TempDir, BufferDir, Keys, GetLocationGenerator,
           DegreesToMeters, PkiMode, Simulated) ->
    ?spawn_server(
       fun(Parent) ->
               init(Parent, Nym, SyncAddress, TempDir, BufferDir, Keys,
                    GetLocationGenerator, DegreesToMeters, PkiMode, Simulated)
       end,
       fun initial_message_handler/1).

initial_message_handler(#state{nym = Nym,
                               keys = {PublicKey, _SecretKey},
                               pki_mode = PkiMode} = State) ->
    receive
        {neighbour_workers, NeighbourWorkers} ->
            case supervisor_helper:get_selected_worker_pids(
                   [maildrop_serv, nodis_serv, pki_serv],
                   NeighbourWorkers) of
                [MaildropServPid, undefined, PkiServPid] ->
                    NodisServPid = whereis(nodis_serv);
                [MaildropServPid, NodisServPid, PkiServPid] ->
                    ok
            end,
            {ok, NodisSubscription} = nodis_serv:subscribe(NodisServPid),
            ok = publish_public_key(PkiServPid, PkiMode, Nym, PublicKey),
            {swap_message_handler, fun message_handler/1,
             State#state{maildrop_serv_pid = MaildropServPid,
                         pki_serv_pid = PkiServPid,
			 nodis_serv_pid = NodisServPid,
                         nodis_subscription = NodisSubscription}}
    end.

%% Exported: stop

-spec stop(pid()) -> ok.

stop(Pid) ->
    serv:call(Pid, stop).

%% Exported: pause

-spec pause(pid()) -> ok.

pause(Pid) ->
    serv:cast(Pid, pause).

%% Exported: resume

-spec resume(pid()) -> ok.

resume(Pid) ->
    serv:cast(Pid, resume).

%% Exported: become_forwarder

-spec become_forwarder(pid(), message_id()) -> ok.

become_forwarder(Pid, MessageId) ->
    serv:cast(Pid, {become_forwarder, MessageId}).

%% Exported: become_nothing

-spec become_nothing(pid()) -> ok.

become_nothing(Pid) ->
    serv:cast(Pid, become_nothing).

%% Exported: become_source

-spec become_source(pid(), binary(), message_id()) -> ok.

become_source(Pid, TargetNym, MessageId) ->
    serv:cast(Pid, {become_source, TargetNym, MessageId}).

%% Exported: become_target

-spec become_target(pid(), message_id()) -> ok.

become_target(Pid, MessageId) ->
    serv:cast(Pid, {become_target, MessageId}).

-spec buffer_read(Pid::pid(), Index::non_neg_integer()) ->
	  {ok,Message::binary()}.

buffer_read(Pid, Index) ->
    serv:call(Pid, {buffer_read, Index}).

-spec buffer_write(Pid::pid(), Index::non_neg_integer(), 
		   Message::binary()) ->
	  ok.

buffer_write(Pid, Index, Message) ->
    serv:call(Pid, {buffer_write, Index, Message}).

-spec buffer_size(pid()) -> integer().

buffer_size(Pid) ->
    serv:call(Pid, buffer_size).

-spec buffer_scramble(Pid::pid(), Index::non_neg_integer()) ->
	  {ok,Message::binary()}.

buffer_scramble(Pid, Index) ->
    serv:call(Pid, {buffer_scramble, Index}).


%% get a list of messages to send
-spec buffer_select(pid(), Factor::float()) -> [integer()].

buffer_select(Pid, F) ->
    serv:call(Pid, {buffer_select, F}).

%% Exported: got_message

-spec got_message(
        pid(), message_id(), binary(), non_neg_integer(), binary()) ->
          ok.

got_message(Pid, Message, SenderNym, Signature, DecryptedData) ->
    serv:cast(Pid, {got_message, Message, SenderNym, Signature,
                    DecryptedData}).

%% Exported: pick_as_source

-spec pick_as_source(pid()) -> ok.

pick_as_source(Pid) ->
    serv:cast(Pid, pick_as_source).

%% Exported: send_message

-spec send_message(pid(), message_id(), binary(), binary()) ->
          ok | {error, any()}.

send_message(Pid, MessageId, RecipientNym, Payload) ->
    serv:call(Pid, {send_message, MessageId, RecipientNym, Payload}).

%% Exported: start_location_updating

-spec start_location_updating(pid()) -> ok.

start_location_updating(Pid) ->
    serv:cast(Pid, start_location_updating).

%% Exported: get_unique_id

-spec get_unique_id() -> pos_integer().

get_unique_id() ->
    erlang:unique_integer([positive]).

%%
%% Server
%%

init(Parent, Nym, SyncAddress, TempDir, BufferDir, Keys,
     GetLocationGenerator, DegreesToMeters, PkiMode, Simulated) ->
    rand:seed(exsss),
    {ok, BufferHandle} = player_buffer:new(BufferDir,
					   ?PLAYER_BUFFER_MAX_SIZE,
					   Simulated),
    case Simulated of
        true ->
            LocationGenerator = GetLocationGenerator();
        false ->
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
                temp_dir = TempDir,
                buffer_dir = BufferDir,
                buffer_handle = BufferHandle,
                message_digests = MessageDigests,
                keys = Keys,
                location_generator = LocationGenerator,
                degrees_to_meters = DegreesToMeters,
                pki_mode = PkiMode,
                simulated = Simulated}}.

message_handler(
  #state{parent = Parent,
         nym = Nym,
         maildrop_serv_pid = MaildropServPid,
         pki_serv_pid = PkiServPid,
         sync_address = SyncAddress,
         temp_dir = TempDir,
         buffer_dir = _BufferDir,
         buffer_handle = BufferHandle,
         message_digests = MessageDigests,
         keys = {_PublicKey, SecretKey} = Keys,
         location_generator = LocationGenerator,
         degrees_to_meters = _DegreesToMeters,
         x = X,
         y = Y,
         neighbour_state = NeighbourState,
	 neighbour_pid = NeighbourPid,
         is_zombie = IsZombie,
         picked_as_source = _PickedAsSource,
         pick_mode = PickMode,
         paused = Paused,
         meters_moved = MetersMoved,
         pki_mode = PkiMode,
         simulated = Simulated,
	 nodis_serv_pid = NodisServPid,
         nodis_subscription = NodisSubscription,
         reserved_message_indices = ReservedMessageIndices} = State) ->
    receive
        config_updated ->
            ?daemon_log_tag_fmt(system, "Player noticed a config change", []),
            noreply;
        {call, From, stop} ->
            {stop, From, ok};
        {cast, pause} ->
            {noreply, State#state{paused = true}};
        {cast, resume} ->
            {noreply, State#state{paused = false}};
        {cast, {become_forwarder, MessageId}} ->
            NewPickMode = {is_forwarder, {message_not_in_buffer, MessageId}},
            case Simulated of
                true ->
                    true = player_db:update(
                             #db_player{nym = Nym, pick_mode = NewPickMode});
                false ->
                    true
            end,
            {noreply, State#state{pick_mode = NewPickMode}};
        {cast, become_nothing} ->
            case Simulated of
                true ->
                    true = player_db:update(
                             #db_player{nym = Nym, pick_mode = is_nothing});
                false ->
                    true
            end,
            {noreply, State#state{pick_mode = is_nothing}};
        {cast, {become_source, TargetNym, MessageId}} ->
            NewPickMode = {is_source, {TargetNym, MessageId}},
            case Simulated of
                true ->
                    true = player_db:update(
                             #db_player{nym = Nym, pick_mode = NewPickMode});
                false ->
                    true
            end,
            {noreply, State#state{pick_mode = NewPickMode}};
        {cast, {become_target, MessageId}} ->
            NewPickMode = {is_target, MessageId},
            case Simulated of
                true ->
                    true = player_db:update(
                             #db_player{nym = Nym, pick_mode = NewPickMode});
                false ->
                    true
            end,
            {noreply, State#state{pick_mode = NewPickMode}};

        {call, From, {buffer_read, Index}} ->
	    Message = player_buffer:read(BufferHandle, Index),
	    {reply, From, {ok, Message}, State};

        {call, From, {buffer_write, Index, Message}} ->
	    ok = player_buffer:write(BufferHandle, Index, Message),
	    if Simulated ->
		    MD5 = erlang:md5(Message),
		    NewPickMode =
			case ets:lookup(player_message, MD5) of
			    [{_,true}] ->
				%% this one of the messages we are looking for
				{is_forwarder, {message_in_buffer, MD5}};
			    [] ->
				{is_forwarder, {message_not_in_buffer, MD5}}
			end,
		    true = player_db:update(
			     #db_player{
				nym = Nym,
				buffer_size =
				    player_buffer:size(BufferHandle),
				pick_mode = NewPickMode}),
		    {reply, From, ok, State#state{pick_mode=NewPickMode}};
	       true ->
		    {reply, From, ok, State}
	    end;

        {call, From, buffer_size} ->
	    {reply, From, player_buffer:size(BufferHandle)};

        {call, From, {buffer_scramble, Index}} ->
	    ok = player_buffer:scramble(BufferHandle, Index),
	    {reply, From, ok, State};

        {call, From, {buffer_select,F}} ->
	    {reply, From, player_buffer:select(BufferHandle,F)};

        {cast, {got_message, _, _, _, _}} when IsZombie ->
            noreply;

        {cast, {got_message, Message, SenderNym, Signature, DecryptedData}} ->
	    MD5 = erlang:md5(Message), %% for simulated message check
            DigestedDecryptedData = erlang:md5(DecryptedData),
            case persistent_circular_buffer:exists(MessageDigests,DigestedDecryptedData) of
                false ->
                    Verified =
			case read_public_key(PkiServPid, PkiMode, SenderNym) of
			    {ok, SenderPublicKey} ->
                                elgamal:verify(Signature, DecryptedData,
                                               SenderPublicKey);
                        {error, _Reason} ->
				false
			end,
                    TempFilename = mail_util:mktemp(TempDir),
                    Mail = DecryptedData,
                    case Verified of
                        true ->
                            ?daemon_log_tag_fmt(
                               system,
                               "~s received a verified message from ~s (~w)",
                               [Nym, SenderNym, MD5]),
                            Footer = <<"\n\nNOTE: This mail is verified">>,
                            MailWithFooter =
                                mail_util:inject_footer(Mail, Footer),
                            ok = file:write_file(TempFilename, MailWithFooter);
                        false ->
                            ?daemon_log_tag_fmt(
                               system,
                               "~s received an *unverified* message from ~s (~w)",
                               [Nym, SenderNym, MD5]),
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
                            %% true = stats_db:message_received(MD5, SenderNym, Nym);
			    true;
                        false ->
                            true
                    end,
                    case PickMode of
                        {is_target, MD5} ->
                            ?dbg_log({target_received_message, Nym, MD5}),
                            simulator_serv:target_received_message(
                              Nym, SenderNym);
                        _ ->
                            ok
                    end,
                    ok = persistent_circular_buffer:add(MessageDigests, DigestedDecryptedData),
                    {noreply, State};
                true ->
                    ?daemon_log_tag_fmt(
                       system, "~s received a duplicated message from ~s (~w)",
                       [Nym, SenderNym, MD5]),
                    case Simulated of
                        true ->
                            %% true = stats_db:message_duplicate_received(
			    %% MD5, SenderNym, Nym);
			    true;
                        false ->
                            true
                    end,
                    noreply
            end;

        {cast, pick_as_source} ->
            {noreply, State#state{picked_as_source = true}};

        {call, From, {send_message, _MessageId, RecipientNym, Mail}} ->
            case read_public_key(PkiServPid, PkiMode, RecipientNym) of
                {ok, RecipientPublicKey} ->
                    EncryptedData = elgamal:uencrypt(Mail, RecipientPublicKey, SecretKey),
		    IndexList = player_buffer:select(BufferHandle,?K),
		    if Simulated -> %% keep track on this message for simulation
			    MD5 = erlang:md5(EncryptedData),
			    ets:insert(player_message, {MD5, true});
		       true ->
			    ok
		    end,
                    ok = write_messages(BufferHandle,EncryptedData,IndexList),
                    case Simulated of
                        true ->
                            true = player_db:update(
                                     #db_player{
                                        nym = Nym,
                                        buffer_size =
                                            player_buffer:size(BufferHandle),
                                        pick_mode = PickMode});
			%% true = stats_db:message_created(MessageId, Nym, RecipientNym);
                        false ->
                            true
                    end,
                    {reply, From, ok};
                {error, Reason} ->
                    {reply, From, {error, Reason}}
            end;
        {cast, start_location_updating} ->
            self() ! {location_updated, 0},
            noreply;
        %%
        %% Nodis subscription events
        %%
        {nodis, NodisSubscription, {pending, NAddr}} ->
            ?DSYNC("Pending: ~p naddr=~p\n", [SyncAddress, NAddr]),
            NeighbourState1 = NeighbourState#{ NAddr => pending },
            NeighbourPid1 = NeighbourPid#{ NAddr => undefined },
            update_neighbours(Simulated, Nym, NeighbourState1),
            {noreply, State#state{neighbour_state=NeighbourState1,
                                  neighbour_pid=NeighbourPid1 }};
        {nodis, NodisSubscription, {up, NAddr}} ->
            ?DSYNC("Up: ~p naddr=~p\n", [SyncAddress, NAddr]),
            ?dbg_log_tag(nodis, {up, NAddr}),
            NeighbourState1 = NeighbourState#{ NAddr => up },
            update_neighbours(Simulated, Nym, NeighbourState1),
            case maps:get(NAddr, NeighbourPid, undefined) of
                undefined when SyncAddress > NAddr ->
                    {ok, Pid} = player_sync_serv:connect(
                                  self(),
                                  NAddr,
                                  #player_sync_serv_options{
                                     simulated =  Simulated,
                                     sync_address = SyncAddress,
                                     f = ?F,
                                     keys = Keys}),
                    %% double map!
                    NeighbourPid1 = NeighbourPid#{ Pid => NAddr, NAddr => Pid},
                    %% update player_db?
                    {noreply, State#state{neighbour_state=NeighbourState1,
                                          neighbour_pid = NeighbourPid1 }};
                undefined ->
                    NeighbourPid1 = NeighbourPid#{ NAddr => undefined },
                    {noreply, State#state{neighbour_state=NeighbourState1,
                                          neighbour_pid=NeighbourPid1 }};

                Pid when is_pid(Pid) ->
                    ?dbg_log_tag(nodis, {up, NAddr}),
                    {noreply, State#state{neighbour_state=NeighbourState1}}
            end;
        {nodis, NodisSubscription, {down,NAddr}} ->
            ?DSYNC("Down: ~p naddr=~p\n", [SyncAddress, NAddr]),
            ?dbg_log_tag(nodis, {down, NAddr}),
            NeighbourState1 = NeighbourState#{ NAddr => down },
            update_neighbours(Simulated, Nym, NeighbourState1),
            case maps:get(NAddr, NeighbourPid, undefined) of
                Pid when is_pid(Pid) ->
                    io:format("Kill sync server ~p\n", [Pid]),
                    exit(Pid, die),
                    {noreply, State#state{neighbour_state=NeighbourState1}};
                _ ->
                    {noreply, State#state{neighbour_state=NeighbourState1}}
            end;
        {nodis, NodisSubscription, {missed, NAddr}} ->
            ?DSYNC("Missed: ~p naddr=~p\n", [SyncAddress, NAddr]),
            ?dbg_log_tag(nodis, {missed, NAddr}),
            noreply;
        {'EXIT', Parent, Reason} ->
            ok = persistent_circular_buffer:close(MessageDigests),
            ok = player_buffer:delete(BufferHandle),
            exit(Reason);
        {'EXIT', Pid, _Reason} = UnknownMessage ->
            UpdatedReservedMessageIndices =
                lists:foldl(
                  fun({ReserverPid, Index}, Acc)
                        when ReserverPid == Pid ->
                          case player_buffer:unreserve(BufferHandle, Index) of
                              ok ->
                                  Acc;
                              {error, Reason} ->
                                  ?error_log({unreserve_failed, Reason}),
                                  Acc
                          end;
                     (PidAndIndex, Acc) ->
                          [PidAndIndex|Acc]
                  end, [], ReservedMessageIndices),
            case maps:get(Pid, NeighbourPid, undefined) of
                NAddr when is_tuple(NAddr) ->
                    NeighbourPid1 = maps:remove(Pid, NeighbourPid),
                    NeighbourPid2 = maps:remove(NAddr, NeighbourPid1),
                    ?DSYNC("Wait: ~p\n", [NAddr]),
                    nodis:wait(NodisServPid, NAddr),
                    NeighbourState1 = NeighbourState#{ NAddr => wait },
                    update_neighbours(Simulated, Nym, NeighbourState1),
                    {noreply,
                     State#state{
                       neighbour_pid = NeighbourPid2,
                       neighbour_state = NeighbourState1,
                       reserved_message_indices =
                           UpdatedReservedMessageIndices}};
                undefined ->
                    ?error_log({unknown_message, UnknownMessage}),
                    {noreply,
                     State#state{
                       reserved_message_indices =
                           UpdatedReservedMessageIndices}}
            end;
        %%
        %% Below follows handling of internally generated messages
        %%
        {location_updated, Timestamp} when Paused ->
            erlang:send_after(1000, self(), {location_updated, Timestamp}),
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
                {{NextTimestamp, NextX, NextY}, NewLocationGenerator} ->
                    if
                        X == none ->
                            ?dbg_log({initial_location, NextX, NextY}),
                            case Simulated of
                                true ->
                                    true = player_db:add(Nym, NextX, NextY);
                                false ->
                                    true
                            end;
                        true ->
                            ?dbg_log({location_updated,
                                      Nym, X, Y, NextX, NextY}),
                            case Simulated of
                                true ->
                                    true = player_db:update(
                                             #db_player{
                                                nym = Nym,
                                                x = NextX,
                                                y = NextY,
                                                buffer_size =
                                                    player_buffer:size(
                                                      BufferHandle),
                                                pick_mode = PickMode});
                                false ->
                                    true
                            end
                    end,
                    ?dbg_log({will_check_location, Nym,
                              NextTimestamp - Timestamp}),
                    NextUpdate = trunc((NextTimestamp - Timestamp) * 1000),
                    erlang:send_after(NextUpdate, self(),
                                      {location_updated, NextTimestamp}),
                    %%ok = print_speed(DegreesToMeters, X, Y, MetersMoved,
                    %%                 Timestamp, NextX, NextY),
                    {noreply,
                     State#state{location_generator = NewLocationGenerator,
                                 x = NextX,
                                 y = NextY,
                                 meters_moved = MetersMoved}}
            end;
        {system, From, Request} ->
            {system, From, Request};
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

%% write multiple copies of Message, player_buffer:write will scramble
%% when needed.
write_messages(_BufferHandle, _Message, []) ->
    ok;
write_messages(BufferHandle, Message, [Index|IndexList]) ->
    ok = player_buffer:write(BufferHandle, Index, Message),
    write_messages(BufferHandle, Message, IndexList).

update_neighbours(true, Nym, Ns) ->
    true = player_db:update(
	     #db_player{ nym = Nym,
			 neighbours = get_player_nyms(Ns)
		       });
update_neighbours(false, _Nym, _Ns) ->
    true.

-spec get_player_nyms(#{ nodis:node_address() => nodis:node_state() }) ->
	  [{string(),nodis:node_state()}].

get_player_nyms(Ns) ->
    List = maps:to_list(Ns),
    States = [St || {_Addr,St} <- List],
    Addresses = [Addr || {Addr,_St} <- List],
    Nyms = simulator_serv:get_player_nyms(Addresses),
    lists:zip(Nyms,States).

%% print_speed(_DegreesToMeters, _X, _Y, _MetersMoved, 0, _NextX, _NextY) ->
%%     ok;
%% print_speed(DegreesToMeters, X, Y, MetersMoved, Timestamp, NextX, NextY) ->
%%     NewMetersMoved =
%%         if
%%             X == none ->
%%                 MetersMoved;
%%             true ->
%%                 VectorLengthInMeters =
%%                     fun(X1, Y1, X2, Y2) ->
%%                             DegreesToMeters(
%%                               math:sqrt(math:pow(X2 - X1, 2) +
%%                                             math:pow(Y2 - Y1, 2)))
%%                     end,
%%                 MetersMoved + VectorLengthInMeters(NextX, NextY, X, Y)
%%         end,
%%     io:format("~w km/h\n", [NewMetersMoved / (Timestamp / 3600) / 1000]),
%%     ok.

%%
%% PKI access functions
%%

read_public_key(PkiServPid, local, Nym) ->
    local_pki_serv:read(PkiServPid, Nym);
read_public_key(_PkiServPid, {global, _PkiPassword, PkiAccess}, Nym) ->
    case pki_network_client:read(
           Nym, #pki_network_client_options{pki_access = PkiAccess},
           ?PKI_NETWORK_TIMEOUT) of
        {ok, #pki_user{public_key = PublicKey}} ->
            {ok, PublicKey};
        {error, Reason} ->
            {error, Reason}
    end.

publish_public_key(PkiServPid, local, Nym, PublicKey) ->
    case local_pki_serv:read(PkiServPid, Nym) of
        {ok, PublicKey} ->
            ?daemon_log_tag_fmt(system, "Local PKI server is in sync", []),
            ok;
        {ok, NewPublicKey} ->
            ok = local_pki_serv:update(PkiServPid, NewPublicKey),
            ?daemon_log_tag_fmt(system, "Updated the local PKI server", []),
            ok;
        {error, no_such_key} ->
            ok = local_pki_serv:create(PkiServPid, PublicKey),
            ?daemon_log_tag_fmt(
               system, "Created an entry in the local PKI server", []),
            ok
    end;
publish_public_key(PkiServPid, {global, PkiPassword, PkiAccess} = PkiMode, Nym,
                   PublicKey) ->
    case pki_network_client:read(
           Nym, #pki_network_client_options{pki_access = PkiAccess},
           ?PKI_NETWORK_TIMEOUT) of
        {ok, #pki_user{public_key = PublicKey}} ->
            ?daemon_log_tag_fmt(system, "Global PKI server is in sync", []),
            ok;
        {ok, PkiUser} ->
            case pki_network_client:update(
                   PkiUser#pki_user{password = PkiPassword,
                                    public_key = PublicKey},
                   #pki_network_client_options{pki_access = PkiAccess},
                   ?PKI_NETWORK_TIMEOUT) of
                ok ->
                    ?daemon_log_tag_fmt(
                       system, "Updated the global PKI server", []),
                    ok;
                {error, Reason} ->
                    ?daemon_log_tag_fmt(
                       system,
                       "Could not update the global PKI server (~p). Will try again in ~w seconds.",
                       [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
                    timer:sleep(?PKI_PUSHBACK_TIME),
                    publish_public_key(PkiServPid, PkiMode, Nym, PublicKey)
            end;
        {error, <<"No such user">>} ->
            case pki_network_client:create(
                   #pki_user{nym = Nym,
                             password = PkiPassword,
                             public_key = PublicKey},
                   #pki_network_client_options{pki_access = PkiAccess},
                   ?PKI_NETWORK_TIMEOUT) of
                ok ->
                    ?daemon_log_tag_fmt(
                       system, "Created an entry in the global PKI server", []),
                    ok;
                {error, Reason} ->
                    ?daemon_log_tag_fmt(
                       system,
                       "Could not create an entry in the global PKI server (~p). Will try again in ~w seconds.",
                       [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
                    timer:sleep(?PKI_PUSHBACK_TIME),
                    publish_public_key(PkiServPid, PkiMode, Nym, PublicKey)
            end;
        {error, Reason} ->
            ?daemon_log_tag_fmt(
               system,
               "Could not contact the global PKI server (~p). Will try again in ~w seconds.",
               [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
            timer:sleep(?PKI_PUSHBACK_TIME),
            publish_public_key(PkiServPid, PkiMode, Nym, PublicKey)
    end.
