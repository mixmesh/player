-module(player_sync_serv).
-export([connect/3]).
-export([start_link/4, stop/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("player/include/player_buffer.hrl").
-include_lib("player/include/player_sync_serv.hrl").

%% Debug: length([erlang:port_info(P)||P <- erlang:ports()]).

-record(state,
        {parent :: pid(),
         options :: #player_sync_serv_options{},
         listen_socket :: inet:socket(),
         acceptors :: [pid()],
         player_serv_pid = not_set :: pid() | not_set}).

%% Exported: connect

connect(PlayerServPid, Port, Options) ->
    Pid = proc_lib:spawn_link(
            fun() -> connect_now(PlayerServPid, Port, Options) end),
    {ok, Pid}.

connect_now(PlayerServPid, Port, #player_sync_serv_options{
                                    ip_address = IpAddress,
                                    connect_timeout = ConnectTimeout,
                                    f = F} = Options) ->
    case gen_tcp:connect(IpAddress, Port,
                         [{active, false}, binary, {packet, 2}],
                         ConnectTimeout) of
        {ok, Socket} ->
            M = erlang:trunc(?PLAYER_BUFFER_MAX_SIZE * F),
            N = erlang:min(M, player_serv:buffer_size(PlayerServPid) * F),
            AdjustedN =
                if N > 0 andalso N < 1 ->
                        1;
                   true ->
                        erlang:trunc(N)
                end,
            case send_messages(PlayerServPid, Socket, AdjustedN, []) of
                ok ->
                    ?dbg_log({connect, send_messages, AdjustedN}),
                    case receive_messages(
                           PlayerServPid, Options, Socket, M, []) of
                        {ok, NewBufferIndices} ->
                            ?dbg_log({connect, receive_messages,
                                      length(NewBufferIndices)}),
                            gen_tcp:close(Socket);
                        {error, closed} ->
                            ok;
                        {error, Reason} ->
                            ok = gen_tcp:close(Socket),
                            ?error_log({connect, receive_message, Reason})
                    end;
                {error, closed} ->
                    ?error_log({connect, premature_socket_close});
                {error, Reason} ->
                    ok = gen_tcp:close(Socket),
                    ?error_log({connect, send_messages, Reason})
            end;
        {error, Reason} ->
            ?error_log({connect, Reason})
    end.

%% Exported: start_link

start_link(Name, {IpAddress, Port}, F, Keys) ->
    ?spawn_server(
       fun(Parent) ->
               init(Parent, Name, Port,
                    #player_sync_serv_options{ip_address = IpAddress,
                                              f = F,
                                              keys = Keys})
       end,
       fun initial_message_handler/1).

%% Exported: stop

stop(Pid) ->
    serv:call(Pid, stop).

%%
%% Server
%%

init(Parent, Name, Port,
     #player_sync_serv_options{
        ip_address = IpAddress} = Options) ->
    Family = if tuple_size(IpAddress) =:= 4 -> [inet];
		tuple_size(IpAddress) =:= 8 -> [inet6];
		true -> []
	     end,
    LOptions = Family ++ [{active, false},
			  {ifaddr, IpAddress},
			  binary,
			  {packet, 2},
			  {reuseaddr, true}],
    {ok, ListenSocket} =
        gen_tcp:listen(Port, LOptions),
    self() ! accepted,
    ?daemon_tag_log(system, "Player sync server starting for ~s on ~s:~w",
                    [Name, inet:ntoa(IpAddress), Port]),
    {ok, #state{parent = Parent,
                options = Options,
                listen_socket = ListenSocket,
                acceptors = []}}.

initial_message_handler(State) ->
    receive
        {sibling_pid, player_serv, PlayerServPid} ->
            {swap_message_handler, fun message_handler/1,
             State#state{player_serv_pid = PlayerServPid}}
    end.

message_handler(#state{parent = Parent,
                       options = Options,
                       listen_socket = ListenSocket,
                       acceptors = Acceptors,
                       player_serv_pid = PlayerServPid} = State) ->
    receive
        {call, From, stop} ->
            {stop, From, ok};
        accepted ->
            Owner = self(),
            Pid =
                proc_lib:spawn_link(
                  fun() ->
                          acceptor(Owner, PlayerServPid, Options, ListenSocket)
                  end),
            {noreply, State#state{acceptors = [Pid|Acceptors]}};
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', PlayerServPid, Reason} ->
            exit(Reason);
        {'EXIT', Parent, Reason} ->
            exit(Reason);
        {'EXIT', Pid, normal} ->
            case lists:member(Pid, Acceptors) of
                true ->
                    {noreply,
                     State#state{acceptors = lists:delete(Pid, Acceptors)}};
                false ->
                    ?error_log({not_an_acceptor, Pid}),
                    noreply
            end;
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

acceptor(Owner, PlayerServPid, #player_sync_serv_options{f = F} = Options,
         ListenSocket) ->
    {ok, Socket} = gen_tcp:accept(ListenSocket),
    Owner ! accepted,
    M = erlang:trunc(?PLAYER_BUFFER_MAX_SIZE * F),
    N = erlang:min(M, player_serv:buffer_size(PlayerServPid) * F),
    AdjustedN =
        if N > 0 andalso N < 1 ->
                1;
           true ->
                erlang:trunc(N)
        end,
    case receive_messages(PlayerServPid, Options, Socket, M, []) of
        {ok, NewBufferIndices} ->
            ?dbg_log({acceptor, receive_messages, length(NewBufferIndices)}),
            case send_messages(PlayerServPid, Socket, AdjustedN,
                               NewBufferIndices) of
                ok ->
                    ?dbg_log({acceptor, send_messages, AdjustedN}),
                    gen_tcp:close(Socket);
                {error, closed} ->
                    ok;
                {error, Reason} ->
                    ?error_log({acceptor, send_messages, Reason}),
                    gen_tcp:close(Socket)
            end;
        {error, closed} ->
            ?error_log({acceptor, premature_socket_close});
        {error, Reason} ->
            ?error_log({acceptor, receive_messages, Reason}),
            gen_tcp:close(Socket)
    end.

%%
%% Send and receive messages
%%

send_messages(_PlayerServPid, Socket, 0, _SkipBufferIndices) ->
    gen_tcp:send(Socket, <<"\r\n">>);
send_messages(PlayerServPid, Socket, N, SkipBufferIndices) ->
    case player_serv:buffer_pop(PlayerServPid, SkipBufferIndices) of
        {ok, <<MessageId:64/unsigned-integer,
               EncryptedData/binary>>} ->
            RandomizedData = elgamal:urandomize(EncryptedData),
            RandomizedMessage =
                <<MessageId:64/unsigned-integer, RandomizedData/binary>>,
            case gen_tcp:send(Socket, RandomizedMessage) of
                ok ->
                    send_messages(PlayerServPid, Socket, N - 1,
                                  SkipBufferIndices);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, no_more_messages} ->
            gen_tcp:send(Socket, <<"\r\n">>)
    end.

receive_messages(_PlayerServPid, _Options, _Socket, 0, NewBufferIndices) ->
    {ok, NewBufferIndices};
receive_messages(PlayerServPid, #player_sync_serv_options{
                                   recv_timeout = RecvTimeout,
                                   keys = {_Public_key, SecretKey}} = Options,
                 Socket, M, NewBufferIndices) ->
    case gen_tcp:recv(Socket, 0, RecvTimeout) of
        {ok, <<"\r\n">>} ->
            {ok, NewBufferIndices};
        {ok, <<MessageId:64/unsigned-integer,
               EncryptedData/binary>> = Message} ->
            case elgamal:udecrypt(EncryptedData, SecretKey) of
                mismatch ->
                    BufferIndex =
                        player_serv:buffer_push(PlayerServPid, Message),
                    receive_messages(PlayerServPid, Options, Socket, M - 1,
                                     [BufferIndex|NewBufferIndices]);
                {SenderNym, Signature, DecryptedData} ->
                    ok = player_serv:got_message(PlayerServPid, MessageId,
                                                 SenderNym, Signature,
                                                 DecryptedData),
                    receive_messages(PlayerServPid, Options, Socket, M - 1,
                                     NewBufferIndices)
            end;
        {ok, InvalidMessage} ->
            ?error_log({invalid_message, InvalidMessage}),
            receive_messages(PlayerServPid, Options, Socket, M - 1,
                             NewBufferIndices);
        {error, Reason} ->
            {error, Reason}
    end.
