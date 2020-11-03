-module(player_buffer).
-export([new/1, new/2, delete/1]).
-export([push/2, pop/2]). %% BEWARE: Will be removed!
-export([inspect/2, replace/2, reserve/1, unreserve/2, swap/3,
         swap/2, size/1, member/2, foldl/3]).
-export_type([buffer_handle/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include("../include/player_buffer.hrl").

-define(LARGEST_POSITIVE_INTEGER, trunc(math:pow(2, 28) / 2)).

-record(buffer_handle,
        {buffer :: ets:tid(),
         file_buffer :: reference(),
         own_indices :: ets:tid(),
         reserved_indices :: ets:tid()}).

-type buffer_handle() :: #buffer_handle{}.

%% Exported: new

-spec new(binary(), boolean()) ->
          {ok, buffer_handle()} |
          {error, invalid_buffer_dir | {file_buffer_corrupt, term()}}.

new(Dir) ->
    new(Dir, false).

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
                    ReservedIndices = ets:new(player_reserved_indices, []),
                    BufferHandle =
                        #buffer_handle{
                           buffer = Buffer,
                           file_buffer = FileBuffer,
                           own_indices = OwnIndices,
                           reserved_indices = ReservedIndices},
                    ok = fill_buffer(Simulated, BufferHandle),
                    {ok, BufferHandle};
                {error, Reason} ->
                    {error, {file_buffer_corrupt, Reason}}
            end;
        false ->
            {error, invalid_buffer_dir}
    end.

%% change PLAYER_BUFFER_MAX_SIZE to 100!
%% (we will have different sized nodes so must fix this any how)
fill_buffer(Simulated, #buffer_handle{buffer = Buffer} = BufferHandle) ->
    BufferSize = ets:info(Buffer, size),
    fill_buffer(Simulated, BufferHandle, ?PLAYER_BUFFER_MAX_SIZE - BufferSize).

fill_buffer(_Simulated, _BufferHandle, N) when N =< 0 ->
    ok;
fill_buffer(true, BufferHandle, N) ->
    %% FAST start
    Message = crypto:strong_rand_bytes(?ENCODED_SIZE),
    _ = push(BufferHandle, <<0:64/unsigned-integer, Message/binary>>),
    fill_buffer(true, BufferHandle, N - 1);
fill_buffer(false, BufferHandle, N) ->
    Message = elgamal:urandomize(crypto:strong_rand_bytes(?ENCODED_SIZE)),
    %% FIXME: DO NOT TO FORGET TO REMOVE message id :-)
    _ = push(BufferHandle, <<0:64/unsigned-integer, Message/binary>>),
    fill_buffer(false, BufferHandle, N - 1).

%% Exported: delete

-spec delete(buffer_handle()) -> ok | {error, term()}.

delete(#buffer_handle{buffer = Buffer,
                      file_buffer = FileBuffer,
                      own_indices = OwnIndices,
                      reserved_indices = ReservedIndices}) ->
    true = ets:delete(Buffer),
    true = ets:delete(OwnIndices),
    true = ets:delete(ReservedIndices),
    dets:close(FileBuffer).

%% Exported: inspect

-spec inspect(buffer_handle(), integer()) ->
          {ok, binary()} | {error, unknown_index}.

inspect(#buffer_handle{buffer = Buffer}, Index) ->
    case ets:lookup(Buffer, Index) of
        [] ->
            {error, unknown_index};
        [{Index, Message}] ->
            {ok, Message}
    end.

%% Exported: push

-spec push(buffer_handle(), binary()) -> integer().

push(BufferHandle, Message) ->
    push(BufferHandle, Message, rand:uniform(?LARGEST_POSITIVE_INTEGER)).

push(#buffer_handle{buffer = Buffer,
                    file_buffer = FileBuffer} = BufferHandle,
     Message, Index) ->
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

pop(#buffer_handle{buffer = Buffer} = BufferHandle, SkipIndices) ->
    pop(BufferHandle, SkipIndices, ets:first(Buffer)).

pop(_BufferHandle, _SkipIndices, '$end_of_table') ->
    {error, no_more_messages};
pop(#buffer_handle{buffer = Buffer,
                   file_buffer = FileBuffer,
                   own_indices = OwnIndices} = BufferHandle,
    SkipIndices, Index) ->
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

replace(#buffer_handle{buffer = Buffer,
                       file_buffer = FileBuffer,
                       own_indices = OwnIndices} = BufferHandle,
        Message, Index) ->
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

make_room(#buffer_handle{buffer = Buffer} = BufferHandle) ->
    make_room(BufferHandle, ets:first(Buffer)).

make_room(_BufferHandle, '$end_of_table') ->
    ok;
make_room(#buffer_handle{buffer = Buffer,
                         file_buffer = FileBuffer,
                         own_indices = OwnIndices,
                         reserved_indices = ReservedIndices} = BufferHandle,
          Index) ->
    case {ets:lookup(OwnIndices, Index), ets:lookup(ReservedIndices, Index)} of
        {[], []} ->
            true = ets:delete(Buffer, Index),
            dets:delete(FileBuffer, Index);
        _ ->
            ?dbg_log({do_not_replace_own_or_reserved_index, Index}),
            make_room(BufferHandle, ets:next(Buffer, Index))
    end.

%% Exported: reserve

-spec reserve(buffer_handle()) ->
          {ok, reference(), binary()} | {error, not_available}.

reserve(#buffer_handle{buffer = Buffer} = BufferHandle) ->
    reserve(BufferHandle, ets:first(Buffer)).

reserve(_BufferHandle, '$end_of_table') ->
    {error, not_available};
reserve(#buffer_handle{buffer = Buffer,
                       reserved_indices = ReservedIndices} = BufferHandle,
        Index) ->
    case ets:lookup(ReservedIndices, Index) of
        [] ->
            Ref = make_ref(),
            true = ets:insert(ReservedIndices, {Index, Ref}),
            [{_, Message}] = ets:lookup(Buffer, Index),
            {ok, Ref, Message};
        [_] ->
            ?dbg_log({already_reserved, Index}),
            reserve(BufferHandle, ets:next(Buffer, Index))
    end.

%% Exported: unreserve

-spec unreserve(buffer_handle(), reference()) ->
          ok | {error, unknown_reservation}.

unreserve(#buffer_handle{reserved_indices = ReservedIndices}, Ref) ->
    case ets:match(ReservedIndices, {'$1', Ref}) of
        [] ->
            {error, unknown_reservation};
        [[Index]] ->
            true = ets:delete(ReservedIndices, Index),
            ok
    end.

%% Exported: swap

-spec swap(buffer_handle(), reference(), binary()) ->
          {ok, integer()} | {error, unknown_reservation}.

swap(#buffer_handle{buffer = Buffer,
                    file_buffer = FileBuffer,
                    own_indices = OwnIndices,
                    reserved_indices = ReservedIndices} = BufferHandle,
     Ref, ReplacementMessage) ->
    case ets:match(ReservedIndices, {'$1', Ref}) of
        [] ->
            {error, unknown_reservation};
        [[Index]] ->
            true = ets:delete(Buffer, Index),
            ok = dets:delete(FileBuffer, Index),
            true = ets:delete(OwnIndices, Index),
            true = ets:delete(ReservedIndices, Index),
            {ok, push(BufferHandle, ReplacementMessage)}
    end.

-spec swap(buffer_handle(), reference()) ->
          {ok, integer()} | {error, unknown_reservation}.

swap(#buffer_handle{buffer = Buffer,
                    file_buffer = FileBuffer,
                    own_indices = OwnIndices,
                    reserved_indices = ReservedIndices} = BufferHandle,
     Ref) ->
    case ets:match(ReservedIndices, {'$1', Ref}) of
        [] ->
            {error, unknown_reservation};
        [[Index]] ->
            true = ets:delete(Buffer, Index),
            ok = dets:delete(FileBuffer, Index),
            true = ets:delete(OwnIndices, Index),
            true = ets:delete(ReservedIndices, Index),
            Message = elgamal:urandomize(crypto:strong_rand_bytes(?ENCODED_SIZE)),
            %% FIXME: DO NOT TO FORGET TO REMOVE message id :-)
            {ok, push(BufferHandle, <<0:64/unsigned-integer, Message/binary>>)}
    end.

%% Exported: size

-spec size(buffer_handle()) -> integer().

size(#buffer_handle{buffer = Buffer}) ->
    ets:info(Buffer, size).

%% Exported: member

-spec member(buffer_handle(), function()) -> boolean().

member(#buffer_handle{buffer = Buffer}, Do) ->
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

foldl(#buffer_handle{buffer = Buffer}, Do, Acc) ->
    foldl(Buffer, Do, Acc, ets:first(Buffer)).

foldl(_Buffer, _Do, Acc, '$end_of_table') ->
    Acc;
foldl(Buffer, Do, Acc, Index) ->
    [{_, Message}] = ets:lookup(Buffer, Index),
    foldl(Buffer, Do, Do(Message, Acc), Index).
