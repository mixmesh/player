-module(player_serv).
-export([start_link/7, stop/1]).
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
-export([update_neighbours/2]).
-export_type([message_id/0, pick_mode/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("simulator/include/player_db.hrl").
-include_lib("player/include/player_serv.hrl").
-include_lib("player/include/player_sync_serv.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include_lib("pki/include/pki_serv.hrl").

-define(GENERATE_MAIL_TIME, (60 * 1000)).
-define(PKI_PUSHBACK_TIME, 10000).

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
         mail_serv_pid = not_set     :: pid() | not_set,
         maildrop_serv_pid = not_set :: pid() | not_set,
         sync_address                :: inet:ip_address(),
         sync_port                   :: inet:port_number(),
         temp_dir                    :: binary(),
         buffer                      :: ets:tid(),
         received_messages = []      :: [integer()],
         generate_mail = false       :: boolean(),
         keys                        :: {#pk{}, #sk{}},     
         reply_keys = not_set        :: {#pk{}, #sk{}} | not_set,
         location_generator          :: fun(),
         degrees_to_meters           :: fun(),
         x = none                    :: integer() | none,
         y = none                    :: integer() | none,
         neighbours = []             :: [#player{}],
         is_zombie = false           :: boolean(),
         picked_as_source = false    :: boolean(),
         pick_mode = is_nothing      :: pick_mode(),
         paused = false              :: boolean(),
         meters_moved = 0            :: integer(),
         simulated                   :: boolean()}).

%% Exported: start_link

start_link(Name, SyncAddress, SyncPort, TempDir, GetLocationGenerator,
           DegreesToMeters, Simulated) ->
    ?spawn_server(
       fun(Parent) ->
               init(Parent, Name, SyncAddress, SyncPort, TempDir,
                    GetLocationGenerator, DegreesToMeters, Simulated)
       end,
       fun initial_message_handler/1).

initial_message_handler(State) ->
    receive
        {sibling_pid, [{mail_serv, MailServPid},
                       {maildrop_serv, MaildropServPid}]} ->
            {swap_message_handler, fun message_handler/1,
             State#state{mail_serv_pid = MailServPid,
                         maildrop_serv_pid = MaildropServPid}}
    end.

%% Exported: stop

stop(Pid) ->
    serv:call(Pid, stop).

%% Exported: pause

pause(Pid) ->
    Pid ! pause,
    ok.

%% Exported: resume

resume(Pid) ->
    Pid ! resume,
    ok.

%% Exported: become_forwarder

become_forwarder(Pid, MessageId) ->
    Pid ! {become_forwarder, MessageId},
    ok.

%% Exported: become_nothing

become_nothing(Pid) ->
    Pid ! become_nothing,
    ok.

%% Exported: become_source

become_source(Pid, TargetName, MessageId) ->
    Pid ! {become_source, TargetName, MessageId},
    ok.

%% Exported: become_target

become_target(Pid, MessageId) ->
    Pid ! {become_target, MessageId},
    ok.

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
    Pid !  {got_message, MessageId, DecryptedData},
    ok.

%% Exported: pick_as_source

pick_as_source(Pid) ->
    Pid ! pick_as_source,
    ok.

%% Exported: send_message

send_message(Pid, MessageId, RecipientName, Letter) ->
    serv:call(Pid, {send_message, MessageId, RecipientName, Letter}).

%% Exported: add_dummy_messages

add_dummy_messages(Pid, N) ->
    serv:call(Pid, {add_dummy_messages, N}).

%% Exported: start_location_updating

start_location_updating(Pid) ->
    Pid ! start_location_updating,
    ok.

%% Exported: stop_generating_mail

stop_generating_mail(Pid) ->
    Pid ! stop_generating_mail,
    ok.

%% Exported: update_neighbours

update_neighbours(Pid, Neighbours) ->
    Pid ! {update_neighbours, Neighbours},
    ok.

%%
%% Server
%%

init(Parent, Name, SyncAddress, SyncPort, TempDir, GetLocationGenerator,
     DegreesToMeters, Simulated) ->
    rand:seed(exsss),
    Buffer = player_buffer:new(),
    {Keys, LocationGenerator} =
        if
            Simulated ->
                {ok, {PublicKey, _} = NewKeys} =
                    simulator_pki_serv:get_keys(Name),
                ok = publish_public_key(Name, <<"baz">>, PublicKey),
                {NewKeys, GetLocationGenerator()};
            true ->
                Password = config:lookup([player, password]),
                [PublicKey, SecretKey] =
                    config:lookup_children(['public-key', 'secret-key'],
                                           config:lookup([player, spiridon])),
                ok = publish_public_key(Name, Password, PublicKey),
                {{PublicKey, SecretKey}, not_set}
        end,
    ?daemon_tag_log(system, "Player server for ~s has been started", [Name]),
    {ok, #state{parent = Parent,
                name = Name,
                sync_address = SyncAddress,
                sync_port = SyncPort,
                temp_dir = TempDir,
                buffer = Buffer,
                keys = Keys,
                location_generator = LocationGenerator,
                degrees_to_meters = DegreesToMeters,
                simulated = Simulated}}.

read_public_key(Name) ->
    case pki_network_client:read(Name) of
        {ok, #pki_user{public_key = PublicKey}} ->
            {ok, PublicKey};
        {error, Reason} ->
            {error, Reason}
    end.

publish_public_key(Name, Password, PublicKey) ->
    case pki_network_client:read(Name) of
        {ok, #pki_user{public_key = PublicKey}} ->
            ?daemon_tag_log(system, "PKI server is in sync", []),
            ok;
        {ok, PkiUser} ->
            case pki_network_client:update(
                   PkiUser#pki_user{password = Password,
                                    public_key = PublicKey}) of
                ok ->
                    ?daemon_tag_log(system, "Updated the PKI server", []),
                    ok;
                {error, Reason} ->
                    ?daemon_tag_log(
                       system,
                       "Could not update the PKI server (~p). Will try again in ~w seconds.",
                       [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
                    timer:sleep(?PKI_PUSHBACK_TIME),
                    publish_public_key(Name, Password, PublicKey)
            end;
        {error, <<"No such user">>} ->
            case pki_network_client:create(
                   #pki_user{name = Name,
                             password = Password,
                             public_key = PublicKey}) of
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
                    publish_public_key(Name, Password, PublicKey)
            end;
        {error, Reason} ->
            ?daemon_tag_log(
               system,
               "Could not contact PKI server (~p). Will try again in ~w seconds.",
               [Reason, trunc(?PKI_PUSHBACK_TIME / 1000)]),
            timer:sleep(?PKI_PUSHBACK_TIME),
            publish_public_key(Name, Password, PublicKey)
    end.

message_handler(
  #state{parent = Parent,
         name = Name,
         mail_serv_pid = MailServPid,
         maildrop_serv_pid = MaildropServPid,
         sync_address = SyncAddress,
         sync_port = SyncPort,
         temp_dir = TempDir,
         buffer = Buffer,
         received_messages = ReceivedMessages,
         generate_mail = GenerateMail,
         keys = Keys,
         location_generator = LocationGenerator,
%         degrees_to_meters = DegreesToMeters,
         x = X,
         y = Y,
         neighbours = Neighbours,
         is_zombie = IsZombie,
         picked_as_source = PickedAsSource,
         pick_mode = PickMode,
         paused = Paused,
         meters_moved = MetersMoved,
         simulated = Simulated} = State) ->
  receive
      {call, From, stop} ->
          {stop, From, ok};
      pause ->
          {noreply, State#state{paused = true}};
      resume ->
          {noreply, State#state{paused = false}};
      {become_forwarder, MessageId} ->
          NewPickMode = {is_forwarder, {message_not_in_buffer, MessageId}},
          if
              Simulated ->
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = NewPickMode});
              true ->
                  true
          end,
          {noreply, State#state{pick_mode = NewPickMode}};
      become_nothing ->
          if
              Simulated ->
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = is_nothing});
              true ->
                  true
          end,
          {noreply, State#state{pick_mode = is_nothing}};
      {become_source, TargetName, MessageId} ->
          NewPickMode = {is_source, {TargetName, MessageId}},
          if
              Simulated ->
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = NewPickMode});
              true ->
                  true
          end,
          {noreply, State#state{pick_mode = NewPickMode}};
      {become_target, MessageId} ->
          NewPickMode = {is_target, MessageId},
          if
              Simulated ->
                  true = player_db:update(#db_player{name = Name,
                                                     pick_mode = NewPickMode});
              true ->
                  true
          end,
          {noreply, State#state{pick_mode = NewPickMode}};
      {call, From, {buffer_pop, SkipBufferIndices}} ->
          case player_buffer:pop(Buffer, SkipBufferIndices) of
              {ok, Message} ->
                  NewPickMode = calculate_pick_mode(Buffer, PickMode),
                  if
                      Simulated ->
                          true = player_db:update(
                                   #db_player{
                                      name = Name,
                                      buffer_size = player_buffer:size(Buffer),
                                      pick_mode = NewPickMode});
                      true ->
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
          if
              Simulated ->
                  true = player_db:update(
                           #db_player{
                              name = Name,
                              buffer_size = player_buffer:size(Buffer),
                              pick_mode = NewPickMode}),
                  true = stats_db:message_buffered(Name);
              true ->
                  true
          end,
          {reply, From, BufferIndex, State#state{pick_mode = NewPickMode}};
      {call, From, buffer_size} ->
          {reply, From, player_buffer:size(Buffer)};
      {got_message, _, _} when IsZombie ->
          noreply;
      {got_message, MessageId, <<MessageId:64/unsigned-integer,
                                 SenderNameSize:8,
                                 SenderName:SenderNameSize/binary,
                                 Letter/binary>>} ->
          case lists:member(MessageId, ReceivedMessages) of
              false ->
                  %%io:format("GOT MESSAGE: ~p\n", [{Name, SenderName}]),
                  TempFilename = mail_util:mktemp(TempDir),
                  ok = file:write_file(TempFilename, Letter),
                  {ok, _} = maildrop_serv:write(MaildropServPid, TempFilename),
                  ok = file:delete(TempFilename),
                  if
                      Simulated ->
                          true = stats_db:message_received(
                                   MessageId, SenderName, Name);
                      true ->
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
                  if
                      Simulated ->
                          true = stats_db:message_duplicate_received(
                                   MessageId, SenderName, Name);
                      true ->
                          true
                  end,
                  noreply
          end;
      pick_as_source ->
          {noreply, State#state{picked_as_source = true}};
      {call, From, {send_message, MessageId, RecipientName, Letter}} ->
          case read_public_key(RecipientName) of
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
                  if
                      Simulated ->
                          true = player_db:update(
                                   #db_player{
                                      name = Name,
                                      buffer_size = player_buffer:size(Buffer),
                                      pick_mode = PickMode}),
                          true = stats_db:message_created(
                                   MessageId, Name, RecipientName);
                      true ->
                          true
                  end,
                  {reply, From, ok};
              {error, Reason} ->
                  {reply, From, {error, Reason}}
          end;
      {call, From, {add_dummy_messages, N}} ->
          RecipientName = <<"p1">>,
          {ok, RecipientPublicKey} = read_public_key(RecipientName),
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
                          if
                              Simulated ->
                                  true = stats_db:message_created(
                                           MessageId, Name, RecipientName);
                              true ->
                                  true
                          end
                  end, N),
          if
              Simulated ->
                  true = player_db:update(
                           #db_player{
                              name = Name,
                              buffer_size = player_buffer:size(Buffer),
                              pick_mode = PickMode});
              true ->
                  true
          end,
          {reply, From, ok};
      start_location_updating ->
          SendMailTime =
              trunc(?GENERATE_MAIL_TIME / 10 +
                        ?GENERATE_MAIL_TIME / 2 * rand:uniform()),
          erlang:send_after(SendMailTime, self(), generate_mail),
          self() ! {location_updated, 0},
          noreply;
      stop_generating_mail ->
          {noreply, State#state{generate_mail = false}};
      {update_neighbours, _NewNeighbours} when IsZombie ->
          noreply;
      {update_neighbours, NewNeighbours} ->
          ?dbg_log({got_new_neighbours, Name, NewNeighbours}),
          lists:foreach(
            fun(#player{sync_address = NeighbourSyncAddress,
                        sync_port = NeighbourSyncPort})
                  when {SyncAddress, SyncPort} >
                       {NeighbourSyncAddress, NeighbourSyncPort} ->
                    _ = player_sync_serv:connect(
                          self(),
                          NeighbourSyncPort,
                          #player_sync_serv_options{
                             address = NeighbourSyncAddress,
                             f = ?F,
                             keys = Keys});
               (_) ->
                    wait_for_neighbour
            end, lists:subtract(NewNeighbours, Neighbours)),
          if
              Simulated ->
                  true = player_db:update(
                           #db_player{
                              name = Name,
                              neighbours = get_names(NewNeighbours)});
              true ->
                  true
          end,
          {noreply, State#state{neighbours = NewNeighbours}};
      %%
      %% Below follows handling of internally generated messages
      %%
      generate_mail when not IsZombie andalso GenerateMail ->
          {RecipientName, _RecipientPublicKey} =
              simulator_pki_serv:get_random_player(Name),
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
                  if
                      Simulated ->
                          true = player_db:update(
                                   #db_player{name = Name, is_zombie = true});
                      true ->
                          true
                  end,
                  {noreply, State#state{is_zombie = true}};
              {{NextTimestamp, NextX, NextY}, NewLocationGenerator} ->
                  if
                      X == none ->
                          ?dbg_log({initial_location, NextX, NextY}),
                          if
                              Simulated ->
                                  true = player_db:add(Name, NextX, NextY);
                              true ->
                                  true
                          end;
                      true ->
                          ?dbg_log({location_updated,
                                    Name, X, Y, NextX, NextY}),
                          if
                              Simulated ->
                                  true = player_db:update(
                                           #db_player{
                                              name = Name,
                                              x = NextX,
                                              y = NextY,
                                              buffer_size = player_buffer:size(Buffer),
                                              pick_mode = PickMode});
                              true ->
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
      {'EXIT', Parent, Reason} ->
          exit(Reason);
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

get_names([]) ->
    [];
get_names([#player{name = Name}|Rest]) ->
    [Name|get_names(Rest)].

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
