-module(player_buffer).
-export([new/0]).
-export([push_many/3, push/2, pop/2]).
-export([size/1]).
-export([member/2]).
-export([foldl/3]).

-include_lib("player/include/player_buffer.hrl").

-define(LARGEST_POSITIVE_INTEGER, trunc(math:pow(2, 28) / 2)).

%% Exported: new

new() ->
    ets:new(player_buffer, [ordered_set]).

%% Exported: push_many

push_many(_Buffer, _Message, 0) ->
    [];
push_many(Buffer, Message, K) ->
    [push(Buffer, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER))|
     push_many(Buffer, Message, K - 1)].

%% Exported: push

push(Buffer, Message) ->
  push(Buffer, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER)).

push(Buffer, Message, Index) ->
    case ets:lookup(Buffer, Index) of
        [] ->
            true = ets:insert(Buffer, {Index, Message}),
            Index;
        _ ->
            push(Buffer, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER))
    end.

%% Exported: pop

pop(Buffer, SkipIndices) ->
    pop(Buffer, SkipIndices, ets:first(Buffer)).

pop(_Buffer, _SkipIndices, '$end_of_table') ->
    {error, no_more_messages};
pop(Buffer, SkipIndices, Index) ->
    case lists:member(Index, SkipIndices) of
        true ->
            pop(Buffer, SkipIndices, ets:next(Buffer, Index));
        false ->
            [{_, Message}] = ets:lookup(Buffer, Index),
            true = ets:delete(Buffer, Index),
            {ok, Message}
    end.

%% Exported: size

size(Buffer) ->
    ets:info(Buffer, size).

%% Exported: member

member(Buffer, Do) ->
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

foldl(Buffer, Do, Acc) ->
    foldl(Buffer, Do, Acc, ets:first(Buffer)).

foldl(_Buffer, _Do, Acc, '$end_of_table') ->
    Acc;
foldl(Buffer, Do, Acc, Index) ->
    [{_, Message}] = ets:lookup(Buffer, Index),
    foldl(Buffer, Do, Do(Message, Acc), Index).
