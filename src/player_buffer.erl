-module(player_buffer).
-export([new/1, new/3, delete/1]).
-export([read/2, write/3, write/4]).
-export([count/2]).
-export([size/1]).
-export([select/2]).

-export_type([buffer_handle/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include("../include/player_buffer.hrl").
-include("player_routing.hrl").

%% buffer layout:
%%  {Index, ReadCount, MD5, Message}
%% MD5 = <<>> when simulated=false
%% otherwis MD5 is md5(Message)
%% 

-record(buffer_handle,
        {simulated = false,
         size :: non_neg_integer(),
         buffer :: ets:tid(),
         file_buffer :: reference()}).

-type buffer_handle() :: #buffer_handle{}.

%% Exported: new

-spec new(Dirname::binary(), Size::non_neg_integer(), 
	  Simulated::boolean()) ->
          {ok, buffer_handle()} |
          {error, invalid_buffer_dir | {file_buffer_corrupt, term()}}.

new(Dir) ->
    new(Dir, ?PLAYER_BUFFER_MAX_SIZE, false).

new(Dir, Size, Simulated) ->
    case filelib:is_dir(Dir) of
        true ->
            BufferFilename = filename:join([Dir, "db"]),
            case dets:open_file({player_buffer, self()},
                                [{file, ?b2l(BufferFilename)}]) of
                {ok, FileBuffer} ->
		    %% FIXME if FileBuffer exit and size > Size then
		    %% it may be trimmed down to Size (by deletion)
		    %% DetsSize = dets:info(FileBuffer, size),
		    %% ok = trim(DetsSize, Size, FileBuffer),
                    Buffer = ets:new(player_buffer, []),
                    true = ets:from_dets(Buffer, FileBuffer),
                    BufferHandle =
                        #buffer_handle{
			   simulated = Simulated,
			   size = Size,
                           buffer = Buffer,
                           file_buffer = FileBuffer
			  },
                    {ok, BufferHandle};
                {error, Reason} ->
                    {error, {file_buffer_corrupt, Reason}}
            end;
        false ->
            {error, invalid_buffer_dir}
    end.

%% remove elements when size is changed
-ifdef(not_used).
trim(DSize, NewSize, Tab) when DSize > NewSize ->
    dets:delete(Tab, DSize),
    trim(DSize-1, NewSize, Tab);
trim(DSize, NewSize, Tab) ->
    ok.
-endif.

%% Exported: size

-spec size(buffer_handle()) -> pos_integer().

size(#buffer_handle{size = Size}) ->
    %% ets:info(Buffer, size).
    Size.

%% Exported: read

%% read a message from the buffer
read(#buffer_handle{simulated = Simulated,
                    buffer = Buffer,
                    size = Size}, Index)
  when is_integer(Index), Index >= 1, Index =< Size ->
    case ets:lookup(Buffer, Index) of
	[{_, 0, _MD5, RoutingHeaderAndMessage}] -> %% fresh message
	    ets:update_counter(Buffer, Index, 1),  %% mark as read
	    RoutingHeaderAndMessage;
	[{_, _RdC, _MD5,
          <<RoutingHeader:?ROUTING_HEADER_SIZE/binary, Message/binary>> =
              RoutingHeaderAndMessage}] ->
            %% if already read we must scramble
	    if
                Simulated ->
		    timer:sleep(100),  %% simulate work
		    RoutingHeaderAndMessage;
                true ->
		    %% FIXME dets insert? 
                    ?l2b([RoutingHeader, elgamal:urandomize(Message)])
	    end;
	[] ->
	    Message = crypto:strong_rand_bytes(?ENCODED_SIZE),
	    if
                Simulated ->
		    timer:sleep(100),  %% simulate work
                    RoutingHeader = player_routing:make_header(blind),
                    ?l2b([RoutingHeader, Message]);
                true ->
                    RoutingHeader = player_routing:make_header(blind),
                    ?l2b([RoutingHeader, elgamal:urandomize(Message)])
	    end
    end.

%% Exported: write

%% write a message + messageid to the buffer
%% we scramble the message before we store it or forward it

write(BufferHandle, Index,
      <<RoutingHeader:?ROUTING_HEADER_SIZE/binary, Message/binary>>) ->
    write(BufferHandle, Index, RoutingHeader, Message).

write(#buffer_handle{simulated = Simulated,
		     buffer = Buffer,
                     file_buffer = FileBuffer,
		     size = Size}, Index, RoutingHeader, Message)
  when is_integer(Index) andalso
       Index >= 1 andalso
       Index =< Size andalso
       is_binary(Message) andalso
       byte_size(Message) =:= ?ENCODED_SIZE andalso
       byte_size(RoutingHeader) =:= ?ROUTING_HEADER_SIZE ->
    if
        Simulated ->
	    timer:sleep(100),  %% simulate work
	    MD5 = erlang:md5(Message),
            RoutingHeaderAndMessage = ?l2b([RoutingHeader, Message]),
	    true = ets:insert(
                     Buffer, {Index, 0, MD5, RoutingHeaderAndMessage}),
	    ok = dets:insert(
                   FileBuffer, {Index, 0, MD5, RoutingHeaderAndMessage});
        true ->
            RoutingHeaderAndMessage =
                ?l2b([RoutingHeader, elgamal:urandomize(Message)]),
	    true = ets:insert(
                     Buffer, {Index, 0, <<>>, RoutingHeaderAndMessage}),
	    ok = dets:insert(
                   FileBuffer, {Index, 0, <<>>, RoutingHeaderAndMessage})
    end.

%% Exported: count

%% count number of messages with matching MD5
count(#buffer_handle{buffer = Buffer}, MD5) ->
    ets:foldl(
      fun({_Index, _RdC, MessageMD5, _Message}, Count) ->
	      if
                  MD5 =:= MessageMD5 ->
		      Count + 1;
                  true ->
		      Count
	      end
      end, 0, Buffer).

%% Exported: select

%% return a uniformly selected list of F*Size  indices in range 1..Size
select(#buffer_handle{size = Size} = BufferHandle, F)
  when is_float(F), F >= 0, F =< 1 ->
    select_(BufferHandle, round(Size * F));
%% of K if selection number is an integer
select(#buffer_handle{size = Size} = BufferHandle, K)
  when is_integer(K), K > 0, K =< Size ->
    select_(BufferHandle, K).

select_(#buffer_handle{size = Size}, N) ->
    element(1, lists:split(N, select__(Size, []))).

select__(0, Acc) ->
    [Index || {_, Index} <- lists:keysort(1,Acc)];
select__(I, Acc) ->
    select__(I-1, [{rand:uniform(), I}|Acc]).

%% Exported: delete

-spec delete(buffer_handle()) -> ok | {error, term()}.

delete(#buffer_handle{buffer = Buffer,
                      file_buffer = FileBuffer}) ->
    true = ets:delete(Buffer),
    dets:close(FileBuffer).
