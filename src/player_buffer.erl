-module(player_buffer).
-export([new/2, delete/1]).
-export([push/2, pop/2, replace/2]).
-export([size/1]).
-export([member/2]).
-export([foldl/3]).
-export_type([buffer_handle/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include("../include/player_buffer.hrl").

-define(LARGEST_POSITIVE_INTEGER, trunc(math:pow(2, 28) / 2)).

%% Exported: new

-type buffer_handle() :: {ets:tid(), reference(), ets:tid()}.
-spec new(binary(), boolean()) ->
          {ok, buffer_handle()} |
          {error, invalid_buffer_dir | {file_buffer_corrupt, term()}}.

new(Dir, Simulated) ->
    case filelib:is_dir(Dir) of
        true ->
            BufferFilename = filename:join([Dir, "db"]),
            case dets:open_file({player_buffer, self()},
                                [{file, ?b2l(BufferFilename)}]) of
                {ok, FileBuffer} ->
                    Buffer = ets:new(player_buffer, [ordered_set]),
                    true = ets:from_dets(Buffer, FileBuffer),
                    OwnIndices = ets:new(player_own_indices, []),
                    BufferHandle = {Buffer, FileBuffer, OwnIndices},
                    ok = fill_buffer(Simulated, BufferHandle),
                    {ok, BufferHandle};
                {error, Reason} ->
                    {error, {file_buffer_corrupt, Reason}}
            end;
        false ->
            {error, invalid_spooler_dir}
    end.

%%
%% NOTE: I just fill the buffer with at most (PLAYER_BUFFER_MAX_SIZE /
%% 10) messages for now. Will change that when I have fixed the message
%% swap exchange in player_sync_serv.erl. Now there will at least be a
%% lot of messages.
%%

fill_buffer(Simulated, {Buffer, _FileBuffer, _OwnIndices} = BufferHandle) ->
    BufferSize = ets:info(Buffer, size),
    fill_buffer(Simulated, BufferHandle,
                trunc(?PLAYER_BUFFER_MAX_SIZE / 10) - BufferSize).

fill_buffer(_Simulated, _BufferHandle, N) when N < 0 ->
    ok;
fill_buffer(true, BufferHandle, N) ->
    Message = crypto:strong_rand_bytes(?ENCODED_SIZE),
    _ = push(BufferHandle, Message),
    fill_buffer(true, BufferHandle, N - 1);
fill_buffer(false, BufferHandle, N) ->
    Message = elgamal:urandomize(crypto:strong_rand_bytes(?MAX_MESSAGE_SIZE)),
    _ = push(BufferHandle, Message),
    fill_buffer(false, BufferHandle, N - 1).

%% Exported: delete

-spec delete(buffer_handle()) -> ok | {error, term()}.

delete({Buffer, FileBuffer, OwnIndices}) ->
    true = ets:delete(Buffer),
    true = ets:delete(OwnIndices),
    dets:close(FileBuffer).

%% Exported: push

-spec push(buffer_handle(), binary()) -> integer().

push(BufferHandle, Message) ->
    push(BufferHandle, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER)).

push({Buffer, FileBuffer, _OwnIndices} = BufferHandle, Message, Index) ->
    case ets:lookup(Buffer, Index) of
        [] ->
            true = ets:insert(Buffer, {Index, Message}),
            ok = dets:insert(FileBuffer, {Index, Message}),
            Index;
        _ ->
            push(BufferHandle, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER))
    end.

%% Exported: pop

-spec pop(buffer_handle(), [integer()]) ->
          {ok, binary()} | {error, no_more_messages}.

pop({Buffer, _FileBuffer, _OwnIndices} = BufferHandle, SkipIndices) ->
    pop(BufferHandle, SkipIndices, ets:first(Buffer)).

pop(_BufferHandle, _SkipIndices, '$end_of_table') ->
    {error, no_more_messages};
pop({Buffer, FileBuffer, OwnIndices} = BufferHandle, SkipIndices, Index) ->
    case lists:member(Index, SkipIndices) of
        true ->
            pop(BufferHandle, SkipIndices, ets:next(Buffer, Index));
        false ->
            [{_, Message}] = ets:lookup(Buffer, Index),
            true = ets:delete(Buffer, Index),
            ok = dets:delete(FileBuffer, Index),
            true = ets:delete(OwnIndices, Index),
            {ok, Message}
    end.

%% Exported: replace

-spec replace(buffer_handle(), binary()) -> integer().

replace(BufferHandle, Message) ->
    replace(BufferHandle, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER)).

replace({Buffer, FileBuffer, OwnIndices} = BufferHandle, Message, Index) ->
    case ets:lookup(Buffer, Index) of
        [] ->
            ok = make_room(BufferHandle),
            true = ets:insert(Buffer, {Index, Message}),
            ok = dets:insert(FileBuffer, {Index, Message}),
            true = ets:insert(OwnIndices, {Index, true}),
            Index;
        _ ->
            replace(BufferHandle, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER))
    end.

make_room({Buffer, _FileBuffer, _OwnIndices} = BufferHandle) ->
    make_room(BufferHandle, ets:first(Buffer)).

make_room(_BufferHandle, '$end_of_table') ->
    ok;
make_room({Buffer, FileBuffer, OwnIndices} = BufferHandle, Index) ->
    case ets:lookup(OwnIndices, Index) of
        [] ->
            true = ets:delete(Buffer, Index),
            dets:delete(FileBuffer, Index);
        [_] ->
            ?dbg_log({do_not_replace_own_index, Index}),
            make_room(BufferHandle, ets:next(Buffer, Index))
    end.

%% Exported: size

-spec size(buffer_handle()) -> integer().

size({Buffer, _FileBuffer, _OwnIndices}) ->
    ets:info(Buffer, size).

%% Exported: member

-spec member(buffer_handle(), function()) -> boolean().

member({Buffer, _FileBuffer, _OwnIndices}, Do) ->
    member(Buffer, Do, ets:first(Buffer)).

member(_Buffer, _Do, '$end_of_table') ->
    false;
member(Buffer, Do, Index) ->
    [{_, Message}] = ets:lookup(Buffer, Index),
    case Do(Message) of
        true ->
            true;
        false ->
            member(Buffer, Do, ets:next(Buffer, Index))
    end.

%% Exported: foldl

-spec foldl(buffer_handle(), function(), any()) -> any().

foldl({Buffer, _FileBuffer, _OwnIndices}, Do, Acc) ->
    foldl(Buffer, Do, Acc, ets:first(Buffer)).

foldl(_Buffer, _Do, Acc, '$end_of_table') ->
    Acc;
foldl(Buffer, Do, Acc, Index) ->
    [{_, Message}] = ets:lookup(Buffer, Index),
    foldl(Buffer, Do, Do(Message, Acc), Index).
