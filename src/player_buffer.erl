-module(player_buffer).
-export([new/1, new/3, delete/1]).
-export([read/2, write/3, scramble/2]).
-export([size/1]).
-export([select/2]).

-export_type([buffer_handle/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include("../include/player_buffer.hrl").

-define(LARGEST_POSITIVE_INTEGER, trunc(math:pow(2, 28) / 2)).

-record(buffer_handle,
        { simulated = false,
	  size :: non_neg_integer(),
	  buffer :: ets:tid(),
	  file_buffer :: reference()
	}).

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
                    Buffer = ets:new(player_buffer, [ordered_set]),
                    true = ets:from_dets(Buffer, FileBuffer),
		    %% maybe trim of some messages when size > max_size?
                    BufferHandle =
                        #buffer_handle{
			   simulated = Simulated,
			   size = Size,
                           buffer = Buffer,
                           file_buffer = FileBuffer
			  },
                    %% ok = fill_buffer(Simulated, BufferHandle),
                    {ok, BufferHandle};
                {error, Reason} ->
                    {error, {file_buffer_corrupt, Reason}}
            end;
        false ->
            {error, invalid_buffer_dir}
    end.

%% Exported: size

-spec size(buffer_handle()) -> pos_integer().

size(#buffer_handle{size=Size}) ->
    %% ets:info(Buffer, size).
    Size.

%% read a message from the buffer
read(#buffer_handle{buffer=Buffer, size=Size}, Index) when
      is_integer(Index), Index >= 1, Index =< Size ->
    case ets:lookup(Buffer, Index) of
	[{_,Message}] ->
	    Message;
	[] ->
            elgamal:urandomize(crypto:strong_rand_bytes(?ENCODED_SIZE))
    end.

%% write a message + messageid to the buffer
%% we scramble the message before we store it or forward it
write(#buffer_handle{simulated=Simulated,
		     buffer=Buffer, file_buffer=FileBuffer,
		     size=Size}, Index, Message) when
      is_integer(Index), Index >= 1, Index =< Size,
      is_binary(Message), byte_size(Message) =:= ?ENCODED_SIZE ->
    Message1 = if Simulated ->
		       Message;
		  true ->
		       elgamal:urandomize(Message)
	       end,
    true = ets:insert(Buffer, {Index, Message1}),
    ok = dets:insert(FileBuffer, {Index, Message1}).

%% scramble a message
%% we shoulde scramble the message when we fail sending it,
%% since it may have been visible on the wire.

scramble(#buffer_handle{simulated=Simulated,
			buffer=Buffer, file_buffer=FileBuffer,
			size=Size}, Index) when
      is_integer(Index), Index >= 1, Index =< Size ->
    if Simulated ->
	    ok;
       true ->
	    case ets:lookup(Buffer, Index) of
		[{_,Message}] ->
		    Message1 = elgamal:urandomize(Message),
		    true = ets:insert(Buffer, {Index, Message1}),
		    ok = dets:insert(FileBuffer, {Index, Message1});
		[] ->
		    ok
	    end
    end.


%% return a uniformly selected list of F*Size  indices in range 1..Size
select(Handle=#buffer_handle{ size=Size }, F) when 
      is_float(F), F >= 0, F =< 1 ->
    select_(Handle, round(Size*F));
%% of K if selection number is an integer
select(Handle=#buffer_handle{ size=Size }, K) when is_integer(K), K > 0, K =< Size ->
    select_(Handle, K).

select_(#buffer_handle{ size=Size }, N) ->
    element(1, lists:split(N, select__(Size, []))).

select__(0, Acc) ->
    [Index || {_,Index} <- lists:keysort(1,Acc)];
select__(I, Acc) ->
    select__(I-1, [{rand:uniform(), I}|Acc]).


-spec delete(buffer_handle()) -> ok | {error, term()}.

delete(#buffer_handle{buffer = Buffer,
                      file_buffer = FileBuffer}) ->
    true = ets:delete(Buffer),
    dets:close(FileBuffer).
