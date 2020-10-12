-module(player_serv).
-export([start_link/10, stop/1]).
-export([pause/1, resume/1]).
-export([become_forwarder/2, become_nothing/1, become_source/3,
         become_target/2]).
-export([buffer_pop/2, buffer_push/2, buffer_size/1]).
-export([got_message/3]).
-export([pick_as_source/1]).
-export([send_message/4]).
-export([add_dummy_messages/2]).
-export([start_location_updating/1]).
-export([stop_generating_mail/1]).
-export_type([message_id/0, pick_mode/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("simulator/include/player_db.hrl").
-include_lib("player/include/player_serv.hrl").
-include_lib("player/include/player_sync_serv.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include_lib("pki/include/pki_serv.hrl").
-include_lib("pki/include/pki_network_client.hrl").

-define(GENERATE_MAIL_TIME, (60 * 1000)).
-define(PKI_PUSHBACK_TIME, 10000).
-define(PKI_NETWORK_TIMEOUT, 20000).

-type message_id() :: integer().
-type pick_mode() :: is_nothing |
                     {is_forwarder,
                      {message_not_in_buffer |
                       message_in_buffer, message_id()}} |
                     {is_source, {TargetName :: binary(), message_id()}} |
                     {is_target, message_id()}.

-record(state,
        {parent                      :: pid(),
         name                        :: binary(),
         password                    :: binary(),
         mail_serv_pid = not_set     :: pid() | not_set,
         maildrop_serv_pid = not_set :: pid() | not_set,
         pki_serv_pid = not_set      :: pid() | not_set,
         sync_address                :: {inet:ip4_address(),
                                         inet:port_number()},
         temp_dir                    :: binary(),
         buffer_dir                  :: binary(),
         buffer                      :: player_buffer:buffer_handle(),
         received_messages = []      :: [integer()],
         generate_mail = false       :: boolean(),
         keys                        :: {#pk{}, #sk{}},
         reply_keys = not_set        :: {#pk{}, #sk{}} | not_set,
         location_generator          :: function(),
         degrees_to_meters           :: function(),
         x = none                    :: integer() | none,
         y = none                    :: integer() | none,
         neighbours = []             :: [{{inet:ip4_address(),
                                           inet:port_number()}, pid() | none}],
         is_zombie = false           :: boolean(),
         picked_as_source = false    :: boolean(),
         pick_mode = is_nothing      :: pick_mode(),
         paused = false              :: boolean(),
         meters_moved = 0            :: integer(),
         pki_mode                    :: local |
                                        {global,
                                         pki_network_client:pki_access()},
         simulated                   :: boolean(),
         nodis_subscription          :: reference() | undefined}).

%% Exported: start_link

start_link(Name, Password, SyncAddress, TempDir, BufferDir, Keys,
           GetLocationGenerator, DegreesToMeters, PkiMode, Simulated) ->
    ?spawn_server(
       fun(Parent) ->
               init(Parent, Name, Password, SyncAddress, TempDir, BufferDir,
                    Keys, GetLocationGenerator, DegreesToMeters, PkiMode,
                    Simulated)
       end,
       fun initial_message_handler/1).

initial_message_handler(#state{name = Name,
                               password = Password,
                               keys = {PublicKey, _SecretKey},
                               pki_mode = PkiMode} = State) ->
    receive
        {sibling_pid, [{mail_serv, MailServPid},
                       {maildrop_serv, MaildropServPid},
                       {nodis_serv, NodisServPid},
                       {pki_serv, PkiServPid}]} ->
            {ok, NodisSubscription} = nodis_srv:subscribe(NodisServPid),
            ok = publish_public_key(PkiServPid, PkiMode, Name, Password,
                                    PublicKey),
            {swap_message_handler, fun message_handler/1,
             State#state{mail_serv_pid = MailServPid,
                         maildrop_serv_pid = MaildropServPid,
                         pki_serv_pid = PkiServPid,
                         nodis_subscription = NodisSubscription}}
    end.

%% Exported: stop

stop(Pid) ->
    serv:call(Pid, stop).

%% Exported: pause

pause(Pid) ->
    serv:cast(Pid, pause).

%% Exported: resume

resume(Pid) ->
    serv:cast(Pid, resume).

%% Exported: become_forwarder

become_forwarder(Pid, MessageId) ->
    serv:cast(Pid, {become_forwarder, MessageId}).

%% Exported: become_nothing

become_nothing(Pid) ->
    serv:cast(Pid, become_nothing).

%% Exported: become_source

become_source(Pid, TargetName, MessageId) ->
    serv:cast(Pid, {become_source, TargetName, MessageId}).

%% Exported: become_target

become_target(Pid, MessageId) ->
    serv:cast(Pid, {become_target, MessageId}).

%% Exported: buffer_pop

buffer_pop(Pid, SkipBufferIndices) ->
    serv:call(Pid, {buffer_pop, SkipBufferIndices}).

%% Exported: buffer_push

buffer_push(Pid, Message) ->
    serv:call(Pid, {buffer_push, Message}).

%% Exported: buffer_size

buffer_size(Pid) ->
    serv:call(Pid, buffer_size).

%% Exported: got_message

got_message(Pid, MessageId, DecryptedData) ->
    serv:cast(Pid, {got_message, MessageId, DecryptedData}).

%% Exported: pick_as_source

pick_as_source(Pid) ->
    serv:cast(Pid, pick_as_source).

%% Exported: send_message

send_message(Pid, MessageId, RecipientName, Letter) ->
    serv:call(Pid, {send_message, MessageId, RecipientName, Letter}).

%% Exported: add_dummy_messages

add_dummy_messages(Pid, N) ->
    serv:call(Pid, {add_dummy_messages, N}).

%% Exported: start_location_updating

start_location_updating(Pid) ->
    serv:cast(Pid, start_location_updating).

%% Exported: stop_generating_mail

stop_generating_mail(Pid) ->
    serv:cast(Pid, stop_generating_mail).

%%
%% Server
%%

init(Parent, Name, Password, SyncAddress, TempDir, BufferDir, Keys,
     GetLocationGenerator, DegreesToMeters, PkiMode, Simulated) ->
    rand:seed(exsss),
    case player_buffer:new(BufferDir) of
        {ok, Buffer} ->
            case Simulated of
                true ->
                    LocationGenerator = GetLocationGenerator();
                false ->
                    LocationGenerator = not_set
            end,
            ?daemon_tag_log(system,
                            "Player server for ~s has been started", [Name]),
            {ok, #state{parent = Parent,
                        name = Name,
                        password = Password,
                        sync_address = SyncAddress,
                        temp_dir = TempDir,
                        buffer_dir = BufferDir,
                        buffer = Buffer,
                        keys = Keys,
                        location_generator = LocationGenerator,
                        degrees_to_meters = DegreesToMeters,
                        pki_mode = PkiMode,
                        simulated = Simulated}};
        {error, Reason} ->
            {error, Reason}
    end.

message_handler(
  #state{parent = Parent,
         name = Name,
         mail_serv_pid = MailServPid,
         maildrop_serv_pid = MaildropServPid,
         pki_serv_pid = PkiServPid,
         sync_address = SyncAddress,
         temp_dir = TempDir,
         buffer_dir = _BufferDir,
         buffer = Buffer,
         received_messages = ReceivedMessages,
         generate_mail = GenerateMail,
         keys = Keys,
         location_generator = LocationGenerator,
         degrees_to_meters = _DegreesToMeters,
         x = X,
         y = Y,
         neighbours = Neighbours,
         is_zombie = IsZombie,
         picked_as_source = PickedAsSource,
         pick_mode = PickMode,
         paused = Paused,
         meters_moved = MetersMoved,
         pki_mode = PkiMode,
         simulated = Simulated,
         nodis_subscription = NodisSubscription} = State) ->
  receive
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
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = NewPickMode});
              false ->
                  true
          end,
          {noreply, State#state{pick_mode = NewPickMode}};
      {cast, become_nothing} ->
          case Simulated of
              true ->
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = is_nothing});
              false ->
                  true
          end,
          {noreply, State#state{pick_mode = is_nothing}};
      {cast, {become_source, TargetName, MessageId}} ->
          NewPickMode = {is_source, {TargetName, MessageId}},
          case Simulated of
              true ->
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = NewPickMode});
              false ->
                  true
          end,
          {noreply, State#state{pick_mode = NewPickMode}};
      {cast, {become_target, MessageId}} ->
          NewPickMode = {is_target, MessageId},
          case Simulated of
              true ->
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = NewPickMode});
              false ->
                  true
          end,
          {noreply, State#state{pick_mode = NewPickMode}};
      {call, From, {buffer_pop, SkipBufferIndices}} ->
          case player_buffer:pop(Buffer, SkipBufferIndices) of
              {ok, Message} ->
                  NewPickMode = calculate_pick_mode(Buffer, PickMode),
                  case Simulated of
                      true ->
                          true = player_db:update(
                                   #db_player{
                                      name = Name,
                                      buffer_size = player_buffer:size(Buffer),
                                      pick_mode = NewPickMode});
                      false ->
                          true
                  end,
                  {reply, From, {ok, Message},
                   State#state{pick_mode = NewPickMode}};
              {error, Reason} ->
                  {reply, From, {error, Reason}}
          end;
      {call, From,
       {buffer_push,
        <<MessageId:64/unsigned-integer, _EncryptedData/binary>> = Message}} ->
          case target_message_id(PickMode) of
              MessageId ->
                  ?dbg_log({forwarding_target_message, Name, MessageId});
              _ ->
                  silence
          end,
          BufferIndex = player_buffer:push(Buffer, Message),
          NewPickMode = calculate_pick_mode(Buffer, PickMode),
          case Simulated of
              true ->
                  true = player_db:update(
                           #db_player{
                              name = Name,
                              buffer_size = player_buffer:size(Buffer),
                              pick_mode = NewPickMode}),
                  true = stats_db:message_buffered(Name);
              false ->
                  true
          end,
          {reply, From, BufferIndex, State#state{pick_mode = NewPickMode}};
      {call, From, buffer_size} ->
          {reply, From, player_buffer:size(Buffer)};
      {cast, {got_message, _, _}} when IsZombie ->
          noreply;
      {cast, {got_message, MessageId, <<MessageId:64/unsigned-integer,
                                        SenderNameSize:8,
                                        SenderName:SenderNameSize/binary,
                                        Letter/binary>>}} ->
          case lists:member(MessageId, ReceivedMessages) of
              false ->
                  %%io:format("GOT MESSAGE: ~p\n", [{Name, SenderName}]),
                  TempFilename = mail_util:mktemp(TempDir),
                  ok = file:write_file(TempFilename, Letter),
                  {ok, _} = maildrop_serv:write(MaildropServPid, TempFilename),
                  ok = file:delete(TempFilename),
                  case Simulated of
                      true ->
                          true = stats_db:message_received(
                                   MessageId, SenderName, Name);
                      false ->
                          true
                  end,
                  case PickMode of
                      {is_target, MessageId} ->
                          ?dbg_log({target_received_message, Name, MessageId}),
                          simulator_serv:target_received_message(
                            Name, SenderName);
                      _ ->
                          ok
                  end,
                  {noreply, State#state{received_messages =
                                            [MessageId, ReceivedMessages]}};
              true ->
                  %%io:format("GOT DUPLICATE MESSAGE: ~p\n",
                  %%          [{Name, SenderName}]),
                  case Simulated of
                      true ->
                          true = stats_db:message_duplicate_received(
                                   MessageId, SenderName, Name);
                      false ->
                          true
                  end,
                  noreply
          end;
      {cast, pick_as_source} ->
          {noreply, State#state{picked_as_source = true}};
      {call, From, {send_message, MessageId, RecipientName, Letter}} ->
          case read_public_key(PkiServPid, PkiMode, RecipientName) of
              {ok, RecipientPublicKey} ->
                  NameSize = size(Name),
                  EncryptedData =
                      belgamal:uencrypt(
                        <<MessageId:64/unsigned-integer,
                          NameSize:8,
                          Name/binary,
                          Letter/binary>>, RecipientPublicKey),
                  Message = <<MessageId:64/unsigned-integer,
                              EncryptedData/binary>>,
                  _ = player_buffer:push_many(Buffer, Message, ?K),
                  case Simulated of
                      true ->
                          true = player_db:update(
                                   #db_player{
                                      name = Name,
                                      buffer_size = player_buffer:size(Buffer),
                                      pick_mode = PickMode}),
                          true = stats_db:message_created(
                                   MessageId, Name, RecipientName);
                      false ->
                          true
                  end,
                  {reply, From, ok};
              {error, Reason} ->
                  {reply, From, {error, Reason}}
          end;
      {call, From, {add_dummy_messages, N}} ->
          RecipientName = <<"p1">>,
          {ok, RecipientPublicKey} =
              read_public_key(PkiServPid, PkiMode, RecipientName),
          perform(fun() ->
                          MessageId = erlang:unique_integer([positive]),
                          NameSize = size(Name),
                          Letter = <<"foo\r\n\r\n">>,
                          EncryptedData =
                              belgamal:uencrypt(
                                <<MessageId:64/unsigned-integer,
                                  NameSize:8,
                                  Name/binary,
                                  Letter/binary>>, RecipientPublicKey),
                          Message =
                              <<MessageId:64/unsigned-integer,
                                EncryptedData/binary>>,
                          _ = player_buffer:push_many(Buffer, Message, ?K),
                          case Simulated of
                              true ->
                                  true = stats_db:message_created(
                                           MessageId, Name, RecipientName);
                              false ->
                                  true
                          end
                  end, N),
          case Simulated of
              true ->
                  true = player_db:update(
                           #db_player{
                              name = Name,
                              buffer_size = player_buffer:size(Buffer),
                              pick_mode = PickMode});
              false ->
                  true
          end,
          {reply, From, ok};
      {cast, start_location_updating} ->
          SendMailTime =
              trunc(?GENERATE_MAIL_TIME / 10 +
                        ?GENERATE_MAIL_TIME / 2 * rand:uniform()),
          erlang:send_after(SendMailTime, self(), generate_mail),
          self() ! {location_updated, 0},
          noreply;
      {cast, stop_generating_mail} ->
          {noreply, State#state{generate_mail = false}};
      %%
      %% Nodis subscription events
      %%
      {nodis, NodisSubscription,
       {up, {Ip0, Ip1, Ip2, Ip3, NeighbourSyncPort} = NeighbourSyncAddress}} ->
          ?dbg_tag_log(nodis, {up, NeighbourSyncAddress}),
          NeighbourSyncIpAddress = {Ip0, Ip1, Ip2, Ip3},
          case lists:keymember({NeighbourSyncIpAddress, NeighbourSyncPort}, 1,
                               Neighbours) of
              false ->
                  case SyncAddress >
                       {NeighbourSyncIpAddress, NeighbourSyncPort} of
                      true ->
                          {ok, Pid} = player_sync_serv:connect(
                                        self(),
                                        NeighbourSyncPort,
                                        #player_sync_serv_options{
                                           ip_address = NeighbourSyncIpAddress,
                                           f = ?F,
                                           keys = Keys});
                      false ->
                          Pid = none
                  end,
                  NewNeighbours =
                      [{{NeighbourSyncIpAddress, NeighbourSyncPort}, Pid}|
                       Neighbours],
                  case Simulated of
                      true ->
                          true = player_db:update(
                                   #db_player{
                                      name = Name,
                                      neighbours =
                                          get_player_names(NewNeighbours)});
                      false ->
                          true
                  end,
                  {noreply, State#state{neighbours = NewNeighbours}};
              true ->
                  noreply
          end;
      {nodis, NodisSubscription,
       {down,
        {Ip0, Ip1, Ip2, Ip3, NeighbourSyncPort}} = NeighbourSyncAddress} ->
          ?dbg_tag_log(nodis, {down, NeighbourSyncAddress}),
          NeighbourSyncIpAddress = {Ip0, Ip1, Ip2, Ip3},
          case lists:keysearch({NeighbourSyncIpAddress, NeighbourSyncPort}, 1,
                               Neighbours) of
              {value, {_, Pid}} ->
                  if
                      is_pid(Pid) ->
                          exit(Pid, die);
                      true ->
                          ok
                  end,
                  NewNeighbours =
                      lists:keydelete(
                        {NeighbourSyncIpAddress, NeighbourSyncPort}, 1,
                        Neighbours),
                  case Simulated of
                      true ->
                          true = player_db:update(
                                   #db_player{
                                      name = Name,
                                      neighbours =
                                          get_player_names(NewNeighbours)});
                      false ->
                          ok
                  end,
                  {noreply, State#state{neighbours = NewNeighbours}};
              false ->
                  noreply
          end;
      {nodis, NodisSubscription, {missed, NeighbourAddress}} ->
          ?dbg_tag_log(nodis, {missed, NeighbourAddress}),
          noreply;
      {'EXIT', Parent, Reason} ->
          exit(Reason);
      {'EXIT', Pid, _Reason} = UnknownMessage ->
          case lists:keysearch(Pid, 2, Neighbours) of
              {value, {{NeighbourSyncIpAddress, NeighbourSyncPort}, Pid}} ->
                  NewNeighbours =
                      lists:keyreplace(
                        Pid, 2, Neighbours,
                        {{NeighbourSyncIpAddress, NeighbourSyncPort}, none}),
                  {noreply, State#state{neighbours = NewNeighbours}};
              false ->
                  ?error_log({unknown_message, UnknownMessage}),
                  noreply
          end;
      %%
      %% Below follows handling of internally generated messages
      %%
      generate_mail when not IsZombie andalso GenerateMail ->
          {RecipientName, _RecipientPublicKey} =
              simulator_serv:get_random_player(Name),
          ok = mail_serv:send_mail(
                 MailServPid, RecipientName, PickedAsSource, <<"FOO">>),
          erlang:send_after(?GENERATE_MAIL_TIME, self(), generate_mail),
          {noreply, State#state{picked_as_source = false}};
      generate_mail ->
          noreply;
      {location_updated, Timestamp} when Paused ->
          erlang:send_after(1000, self(), {location_updated, Timestamp}),
          noreply;
      {location_updated, Timestamp} ->
          case LocationGenerator() of
              end_of_locations ->
                  case Simulated of
                      true ->
                          true = player_db:update(
                                   #db_player{name = Name, is_zombie = true});
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
                                  true = player_db:add(Name, NextX, NextY);
                              false ->
                                  true
                          end;
                      true ->
                          ?dbg_log({location_updated,
                                    Name, X, Y, NextX, NextY}),
                          case Simulated of
                              true ->
                                  true = player_db:update(
                                           #db_player{
                                              name = Name,
                                              x = NextX,
                                              y = NextY,
                                              buffer_size =
                                                  player_buffer:size(Buffer),
                                              pick_mode = PickMode});
                              false ->
                                  true
                          end
                  end,
                  ?dbg_log({will_check_location, Name,
                            NextTimestamp - Timestamp}),
                  NextUpdate = trunc((NextTimestamp - Timestamp) * 1000),
                  erlang:send_after(NextUpdate, self(),
                                    {location_updated, NextTimestamp}),
%%                  ok = print_speed(DegreesToMeters, X, Y, MetersMoved,
%%                                   Timestamp, NextX, NextY),
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

perform(_Do, 0) ->
    ok;
perform(Do, N) ->
    Do(),
    perform(Do, N - 1).

%%extract_mail_body(Letter) ->
%%  string:trim(string:find(Letter, <<"\r\n\r\n">>)).

target_message_id(is_nothing) ->
    false;
target_message_id({is_forwarder, {_, MessageId}}) ->
    MessageId;
target_message_id({is_source, {_, MessageId}}) ->
    MessageId;
target_message_id({is_target, MessageId}) ->
    MessageId.

calculate_pick_mode(Buffer, {is_forwarder, {_, MessageId}}) ->
    IsMember =
        player_buffer:member(
          Buffer,
          fun(<<BufferMessageId:64/unsigned-integer,
                _EncryptedData/binary>>)
                when BufferMessageId == MessageId ->
                  true;
             (_) ->
                  false
          end),
    if
        IsMember ->
            {is_forwarder, {message_in_buffer, MessageId}};
        true ->
            {is_forwarder, {message_not_in_buffer, MessageId}}
    end;
calculate_pick_mode(_Buffer, PickMode) ->
    PickMode.

get_player_names(Neighbours) ->
    simulator_serv:get_player_names(
      [SyncAddress || {SyncAddress, _Pid} <- Neighbours]).

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

read_public_key(PkiServPid, local, Name) ->
    case pki_serv:read(PkiServPid, Name) of
        {ok, #pki_user{public_key = PublicKey}} ->
            {ok, PublicKey};
        {error, Reason} ->
            {error, Reason}
    end;
read_public_key(_PkiServPid, {global, PkiAccess}, Name) ->
    case pki_network_client:read(
           Name, #pki_network_client_options{pki_access = PkiAccess},
           ?PKI_NETWORK_TIMEOUT) of
        {ok, #pki_user{public_key = PublicKey}} ->
            {ok, PublicKey};
        {error, Reason} ->
            {error, Reason}
    end.

publish_public_key(PkiServPid, local, Name, Password, PublicKey) ->
    case pki_serv:read(PkiServPid, Name) of
        {ok, #pki_user{public_key = PublicKey}} ->
            ?daemon_tag_log(system, "PKI server is in sync", []),
            ok;
        {ok, PkiUser} ->
            ok = pki_serv:update(PkiServPid,
                                 PkiUser#pki_user{password = Password,
                                                  public_key = PublicKey}),
            ?daemon_tag_log(system, "Updated the PKI server", []),
            ok;
        {error, no_such_user} ->
            ok = pki_serv:create(PkiServPid,
                                 #pki_user{name = Name,
                                           password = Password,
                                           public_key = PublicKey}),
            ?daemon_tag_log(system, "Created an entry in the PKI server", []),
            ok
    end;
publish_public_key(PkiServPid, {global, PkiAccess} = PkiMode, Name, Password,
                   PublicKey) ->
    case pki_network_client:read(
           Name, #pki_network_client_options{pki_access = PkiAccess},
           ?PKI_NETWORK_TIMEOUT) of
        {ok, #pki_user{public_key = PublicKey}} ->
            ?daemon_tag_log(system, "PKI server is in sync", []),
            ok;
        {ok, PkiUser} ->
            case pki_network_client:update(
                   PkiUser#pki_user{password = Password,
                                    public_key = PublicKey},
                   #pki_network_client_options{pki_access = PkiAccess},
                   ?PKI_NETWORK_TIMEOUT) of
                ok ->
                    ?daemon_tag_log(system, "Updated the PKI server", []),
                    ok;
                {error, Reason} ->
                    ?daemon_tag_log(
                       system,
                       "Could not update the PKI server (~p). Will try again in ~w seconds.",
                       [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
                    timer:sleep(?PKI_PUSHBACK_TIME),
                    publish_public_key(PkiServPid, PkiMode, Name, Password,
                                       PublicKey)
            end;
        {error, <<"No such user">>} ->
            case pki_network_client:create(
                   #pki_user{name = Name,
                             password = Password,
                             public_key = PublicKey},
                   #pki_network_client_options{pki_access = PkiAccess},
                   ?PKI_NETWORK_TIMEOUT) of
                ok ->
                    ?daemon_tag_log(
                       system, "Created an entry in the PKI server", []),
                    ok;
                {error, Reason} ->
                    ?daemon_tag_log(
                       system,
                       "Could not create an entry in the PKI server (~p). Will try again in ~w seconds.",
                       [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
                    timer:sleep(?PKI_PUSHBACK_TIME),
                    publish_public_key(PkiServPid, PkiMode, Name, Password,
                                       PublicKey)
            end;
        {error, Reason} ->
            ?daemon_tag_log(
               system,
               "Could not contact PKI server (~p). Will try again in ~w seconds.",
               [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
            timer:sleep(?PKI_PUSHBACK_TIME),
            publish_public_key(PkiServPid, PkiMode, Name, Password,
                               PublicKey)
    end.
