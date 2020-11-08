-module(player_sync_serv).
-export([connect/3]).
-export([start_link/5, stop/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include("../include/player_buffer.hrl").
-include("../include/player_sync_serv.hrl").

%%-define(DSYNC(F,A), io:format((F),(A))).
-define(DSYNC(F,A), ok).
-define(FSYNC(F,A), io:format((F),(A))).

-define(SEND_TIMEOUT, 5000).  %% never wait more than T1 ms to send a message
-define(MAX_CLOSE_MESSAGES, (?PLAYER_BUFFER_MAX_SIZE div 10)).
%% Debug: length([erlang:port_info(P)||P <- erlang:ports()]).

-record(state,
        {parent :: pid(),
         options :: #player_sync_serv_options{},
         listen_socket :: inet:socket(),
         acceptors :: [pid()],
	 nodis_serv_pid :: pid() | undefined,
         player_serv_pid = not_set :: pid() | not_set}).

%% Exported: connect

connect(PlayerServPid, NAddr, Options) ->
    Pid = proc_lib:spawn_link(
            fun() -> connect_now(PlayerServPid, NAddr, Options) end),
    {ok, Pid}.

connect_now(PlayerServPid, NAddr, #player_sync_serv_options{
				     sync_address = SyncAddress,
				     %% ip_address = IpAddress,
				     connect_timeout = ConnectTimeout
				    } = Options) ->
    {_, SrcPort} = SyncAddress,
    {DstIP,DstPort} = NAddr,
    ?DSYNC("Connect: ~p naddr=~p\n", [SyncAddress, NAddr]),
    case gen_tcp:connect(DstIP, DstPort,
                         [{active, false},
			  {nodelay, true},
			  {port,SrcPort+1},
			  {sndbuf, 8+?ENCODED_SIZE},
			  {send_timeout, ?SEND_TIMEOUT},
			  binary],
                         ConnectTimeout) of
        {ok, Socket} ->
	    sync_messages(PlayerServPid, Socket, Options);
        {error, eaddrinuse} ->
	    ok;
        {error, Reason} ->
	    ?FSYNC("Connect fail ~p: ~p naddr:~p\n",
		   [Reason, SyncAddress, NAddr]),
            ?error_log({connect, Reason})
    end.


%% Exported: start_link

start_link(Nym, {IpAddress, Port}, F, Keys, Simulated) ->
    ?spawn_server(
       fun(Parent) ->
               init(Parent, Nym, Port,
                    #player_sync_serv_options{simulated=Simulated,
					      ip_address = IpAddress,
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

init(Parent, Nym, Port,
     #player_sync_serv_options{
        ip_address = IpAddress} = Options) ->
    Family = if tuple_size(IpAddress) =:= 4 -> [inet];
		tuple_size(IpAddress) =:= 8 -> [inet6];
		true -> []
	     end,
    LOptions = Family ++ [{reuseaddr, true},
			  {ifaddr, IpAddress},
			  {active, false},
			  {nodelay, true},
			  {sndbuf, 8+?ENCODED_SIZE},
			  {send_timeout, ?SEND_TIMEOUT},
			  binary],
    {ok, ListenSocket} =
        gen_tcp:listen(Port, LOptions),
    self() ! accepted,
    ?daemon_log_tag_fmt(
       system, "Player sync server starting for ~s on ~s:~w",
       [Nym, inet:ntoa(IpAddress), Port]),
    {ok, #state{parent = Parent,
                options = Options,
                listen_socket = ListenSocket,
                acceptors = []}}.

initial_message_handler(State) ->
    receive
        {neighbour_workers, NeighbourWorkers} ->
            case supervisor_helper:get_selected_worker_pids(
		   [player_serv, nodis_serv], NeighbourWorkers) of
		[PlayerServPid, undefined] ->
		    NodisServPid = whereis(nodis_serv);
		[PlayerServPid, NodisServPid] ->
		    ok
	    end,
            {swap_message_handler, fun message_handler/1,
             State#state{player_serv_pid = PlayerServPid,
			 nodis_serv_pid = NodisServPid}}
    end.

message_handler(#state{parent = Parent,
                       options = Options,
                       listen_socket = ListenSocket,
                       acceptors = Acceptors,
                       player_serv_pid = PlayerServPid,
		       nodis_serv_pid = NodisServPid
		      } = State) ->
    receive
        {call, From, stop} ->
            {stop, From, ok};
        accepted ->
            Owner = self(),
            Pid =
                proc_lib:spawn_link(
                  fun() ->
                          acceptor(Owner, PlayerServPid, NodisServPid,
				   Options, ListenSocket)
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

acceptor(Owner, PlayerServPid, NodisServPid, Options, ListenSocket) ->
    %% check failure reason of ListenSocket (reload, interface error etc)
    {ok, Socket} = gen_tcp:accept(ListenSocket),
    {ok, SyncAddress} = inet:sockname(Socket),
    %% Node we may fail to lookup correct fake address if
    %% connecting side is not fast enough to register socket!
    {ok, {IP,SrcPort}} = inet:peername(Socket),
    NAddr = {IP,SrcPort-1},  %% this MUSt be the nodis address
    case nodis:get_state(NodisServPid, NAddr) of
	up when SyncAddress < NAddr ->
	    Owner ! accepted,
	    ?DSYNC("Accept: ~p, naddr=~p\n", [SyncAddress,NAddr]),
	    sync_messages(PlayerServPid, Socket, Options);
	_State -> %% SyncAddress > NAddr | State != up
	    %% try to close nicly
	    ok = gen_tcp:shutdown(Socket, write),
	    sync_recv(PlayerServPid, Socket, 0, Options),
	    ?DSYNC("Reject: ~p, naddr=~p:~s\n", [SyncAddress, NAddr, _State]),
	    acceptor(Owner, PlayerServPid, NodisServPid, Options, ListenSocket)
    end.


sync_messages(PlayerServPid, Socket, Options) ->
    F = Options#player_sync_serv_options.f,
    IndexList = player_serv:buffer_select(PlayerServPid, F),
    case sync_messages_(PlayerServPid, Socket, IndexList, 0, Options) of
	{ok,K} ->
	    io:format("Synced ~w\n", [K]);
	{error,K,Error} ->
	    io:format("Synced ~w, error ~w\n", [K, Error])
    end.

sync_messages_(PlayerServPid, Socket, [], K, Options) ->
    %% we have no more messages to send so we shutdown our sending side
    %% and read messages until we get a close from the otherside
    %% FIXME: we need total timer here and a max count 
    case gen_tcp:shutdown(Socket, write) of
	ok ->
	    sync_recv(PlayerServPid, Socket, K, Options);
	{error,Reason} ->
	    ?error_log({shutdown, sync_messages, Reason}),
	    {error, K, Reason}
    end;
sync_messages_(PlayerServPid, Socket, [Index|IndexList], K, Options) ->
    {ok,SMessage} = player_serv:buffer_read(PlayerServPid, Index),
    case gen_tcp:send(Socket, SMessage) of
	ok ->
	    case gen_tcp:recv(Socket, ?ENCODED_SIZE,
			      Options#player_sync_serv_options.recv_timeout) of
		{ok, RMessage} ->
		    {_,SecretKey} = Options#player_sync_serv_options.keys,
		    case elgamal:udecrypt(RMessage, SecretKey) of
			mismatch ->
			    ok = player_serv:buffer_write(PlayerServPid, Index, RMessage),
			    sync_messages_(PlayerServPid, Socket, IndexList, K+1, Options);
			{SenderNym, Signature, DecryptedData} ->
			    ok = player_serv:got_message(PlayerServPid,
							 RMessage,
							 SenderNym, 
							 Signature,
							 DecryptedData),
			    sync_messages_(PlayerServPid, Socket, IndexList,
					   K+1, Options)
		    end;
		{error, closed} ->
		    gen_tcp:close(Socket),
		    {error, K, closed};
		%% sync_send_(PlayerServPid, Socket, IndexList, K, Options);
		{error, Reason} ->
		    ?error_log({recv, sync_messages, Reason}),
		    gen_tcp:close(Socket),
		    {error, K, Reason}
	    end;
	{error, Reason} -> 
	    ?error_log({send, sync_messages, Reason}),
	    gen_tcp:close(Socket),
	    {error, K, Reason}
    end.

sync_send_(_PlayerServPid, Socket, [], K, _Options) ->
    %% reading side is close, close when we are done sending
    gen_tcp:close(Socket),
    {ok,K};
sync_send_(PlayerServPid, Socket, [Index|IndexList], K, Options) ->
    {ok,SMessage} = player_serv:buffer_read(PlayerServPid, Index),
    case gen_tcp:send(Socket, SMessage) of
	ok ->
	    sync_send_(PlayerServPid, Socket, IndexList, K+1, Options);
	{error, Reason} ->
	    ?error_log({send, sync_messages, Reason}),
	    {error, K, Reason}
    end.

%% when we have written our messages we wait for other side to terminate
%% since we in general want other side to close properly send a FIN and
%% get a FIN ACK, otherwise it will be RST and WAIT..

sync_recv(PlayerServPid, Socket, K, Options) ->
    sync_recv_(PlayerServPid, Socket, K, ?MAX_CLOSE_MESSAGES, Options).

sync_recv_(_PlayerServPid, Socket, K, 0, _Options) ->
    %% force close
    gen_tcp:close(Socket),
    ?error_log({sync_close, forced_close}),
    {error, K, forced};
sync_recv_(PlayerServPid, Socket, K, I, Options) ->
    case gen_tcp:recv(Socket, ?ENCODED_SIZE, 
		      Options#player_sync_serv_options.recv_timeout) of
	{error, closed} -> %% we got a close and everything is good!
	    gen_tcp:close(Socket),
	    {ok,K};
	{ok, RMessage} ->
	    %% EXPERIMENTAL: since testing decrypt is a relative cheap operation we can check
	    %% for messages to US while trying to sync close with a BIGGER node (but not forever)
	    {_,SecretKey} = Options#player_sync_serv_options.keys,
	    case elgamal:udecrypt(RMessage, SecretKey) of
		mismatch ->
		    sync_recv_(PlayerServPid, Socket, K, I-1, Options);
		{SenderNym, Signature, DecryptedData} ->
		    ok = player_serv:got_message(PlayerServPid, RMessage,
						 SenderNym, Signature,
						 DecryptedData),
		    sync_recv_(PlayerServPid, Socket, K, I-1, Options)
	    end;
	{error, Reason} ->
	    ?error_log({recv, sync_messages, Reason}),
	    gen_tcp:close(Socket),
	    {error, K, Reason}
    end.
