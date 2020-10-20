-module(player_buffer).
-export([new/1]).
-export([push_many/3, push/2, pop/2]).
-export([size/1]).
-export([member/2]).
-export([foldl/3]).
-export_type([buffer_handle/0]).

-include_lib("obscrete/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("player/include/player_buffer.hrl").

-define(LARGEST_POSITIVE_INTEGER, trunc(math:pow(2, 28) / 2)).

%% Exported: new

-type buffer_handle() :: {ets:tid(), reference()}.
-spec new(binary()) ->
          {ok, buffer_handle()} |
          {error, invalid_buffer_dir | {file_buffer_corrupt, term()}}.

new(Dir) ->
    case filelib:is_dir(Dir) of
        true ->
            BufferFilename = filename:join([Dir, "db"]),
            case dets:open_file({player_buffer, self()},
                                [{file, ?b2l(BufferFilename)}]) of
                {ok, FileBuffer} ->
                    Buffer = ets:new(player_buffer, [ordered_set]),
                    true = ets:from_dets(Buffer, FileBuffer),
                    {ok, {Buffer, FileBuffer}};
                {error, Reason} ->
                    {error, {file_buffer_corrupt, Reason}}
            end;
        false ->
            {error, invalid_spooler_dir}
    end.

%% Exported: push_many

-spec push_many(buffer_handle(), binary(), integer()) -> [integer()].

push_many(_BufferHandle, _Message, 0) ->
    [];
push_many(BufferHandle, Message, K) ->
    [push(BufferHandle, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER))|
     push_many(BufferHandle, Message, K - 1)].

%% Exported: push

-spec push(buffer_handle(), binary()) -> integer().

push(BufferHandle, Message) ->
    push(BufferHandle, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER)).

push({Buffer, FileBuffer} = BufferHandle, Message, Index) ->
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

pop({Buffer, _FileBuffer} = BufferHandle, SkipIndices) ->
    pop(BufferHandle, SkipIndices, ets:first(Buffer)).

pop(_BufferHandle, _SkipIndices, '$end_of_table') ->
    {error, no_more_messages};
pop({Buffer, FileBuffer} = BufferHandle, SkipIndices, Index) ->
    case lists:member(Index, SkipIndices) of
        true ->
            pop(BufferHandle, SkipIndices, ets:next(Buffer, Index));
        false ->
            [{_, Message}] = ets:lookup(Buffer, Index),
            true = ets:delete(Buffer, Index),
            ok = dets:delete(FileBuffer, Index),
            {ok, Message}
    end.

%% Exported: size

-spec size(buffer_handle()) -> integer().

size({Buffer, _FileBuffer}) ->
    ets:info(Buffer, size).

%% Exported: member

-spec member(buffer_handle(), function()) -> boolean().

member({Buffer, _FileBuffer}, Do) ->
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

foldl({Buffer, _FileBuffer}, Do, Acc) ->
    foldl(Buffer, Do, Acc, ets:first(Buffer)).

foldl(_Buffer, _Do, Acc, '$end_of_table') ->
    Acc;
foldl(Buffer, Do, Acc, Index) ->
    [{_, Message}] = ets:lookup(Buffer, Index),
    foldl(Buffer, Do, Do(Message, Acc), Index).
