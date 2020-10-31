-module(sss).
-compile(export_all).

start() ->
    Message = <<"FOOBAR">>,
    listen({127, 0, 0, 1}, 10000, Message, 5, 10),
    connect({127, 0, 0, 1}, 10000, Message, 10, 20).

listen(ListenAddress, ListenPort, Message, M, N) ->
    case gen_tcp:listen(ListenPort,
                        [{ip, ListenAddress},
                         {mode, binary},
                         {packet, raw},
                         {active, false},
                         {nodelay, true},
                         {reuseaddr, true},
                         {exit_on_close, false},
                         {send_timeout, 5000},
                         {sndbuf, size(Message)}]) of 
        {ok, ListenSocket} ->
            spawn(fun() -> accept(Message, M, N, ListenSocket) end);
        {error, Reason} ->
            {error, Reason}
    end.

accept(Message, M, N, ListenSocket) ->
    {ok, Socket} = gen_tcp:accept(ListenSocket),
    swap(accept, Message, size(Message), M, N, Socket),
    spawn(fun() -> accept(Message, M, N, ListenSocket) end).

connect(TargetAddress, TargetPort, Message, M, N) ->
    case gen_tcp:connect(TargetAddress, TargetPort,
                         [{mode, binary},
                          {packet, raw},
                          {active, false},
                          {nodelay, true},
                          {exit_on_close, false},
                          {send_timeout, 5000},
                          {sndbuf, size(Message)}]) of 
        {ok, Socket} ->
            swap(connect, Message, size(Message), M, N, Socket);
        {error, Reason} ->
            {error, Reason}
    end.

swap(Type, _Message, _MessageSize, 0, _N, _Socket) ->
    print(Type, swap_done);
swap(Type, Message, MessageSize, M, N, Socket) ->
    timer:sleep(1000),
    print(Type, swap_before_send),
    case gen_tcp:send(Socket, Message) of
        ok ->
            print(Type, swap_before_recv),
            case gen_tcp:recv(Socket, MessageSize) of
                {ok, Message} ->
                    swap(Type, Message, MessageSize, M - 1, N - 1, Socket);
                {error, closed} ->
                    recv_only(Type, Message, MessageSize, M, N, Socket);
                {error, _Reason} ->
                    print(Type, swap_recv_error)
            end;
        {error, closed} ->
            send_only(Type, Message, M, N, Socket);
        {error, _Reason} ->
            print(Type, swap_send_error)
    end.

recv_only(Type, _Message, _MessageSize, _M, 0, _Socket) ->
    print(Type, recv_only_done);
recv_only(Type, Message, MessageSize, M, N, Socket) ->
    timer:sleep(1000),
    print(Type, recv_only_before_recv),
    case gen_tcp:recv(Socket, MessageSize) of
        {ok, Message} ->
            recv_only(Type, Message, MessageSize, M - 1, N - 1, Socket);
        {error, closed} ->
            print(Type, recv_only_closed);
        {error, _Reason} ->
            print(Type, recv_only_error)
    end.

send_only(Type, _Message, _M, 0, _Socket) ->
    print(Type, send_only_done);
send_only(Type, Message, M, N, Socket) ->
    timer:sleep(1000),
    print(Type, send_only_before_send),
    case gen_tcp:send(Socket, Message) of
        ok ->
            send_only(Type, Message, M - 1, N - 1, Socket);
        {error, closed} ->
            print(Type, send_only_closed);
        {error, _Reason} ->
            print(Type, send_only_error)
    end.

print(Mode, Status) ->
    io:format("~w: ~w\n", [Mode, Status]).
