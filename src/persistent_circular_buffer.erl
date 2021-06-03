-module(persistent_circular_buffer).
-export([open/3, close/1, exists/2, add/2]).

%%
%% Exported: open
%%

open(Name, Filename, MaxSize) ->
    case dets:open_file(Name, [{file, Filename}]) of
        {ok, Db} ->
            case dets:lookup(Db, header) of
                [] ->
                    ok = dets:insert(Db, {header, MaxSize, no_head, no_tail}),
                    {ok, Db};
                [_] ->
                    {ok, Db}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%%
%% Exported: close
%%

close(Db) ->
    dets:close(Db).

%%
%% Exported: exists
%%

exists(Db, Digest) ->
    length(dets:lookup(Db, Digest)) == 1.

%%
%% Exported: add
%%

add(Db, NewDigest) ->
    ok = dets:insert(Db, {NewDigest, no_next}),
    case dets:lookup(Db, header) of
        [{header, MaxSize, no_head, no_tail}] ->
            ok = dets:insert(Db, {header, MaxSize, NewDigest, NewDigest});
        [{header, MaxSize, HeadDigest, TailDigest}] ->
            ok = dets:insert(Db, {HeadDigest, NewDigest}),
            case dets:info(Db, size) - 1 > MaxSize of
                true ->
                    [{_, NewTailDigest}] = dets:lookup(Db, TailDigest),
                    ok = dets:delete(Db, TailDigest),
                    ok = dets:insert(
                           Db, {header, MaxSize, NewDigest, NewTailDigest});
                false ->
                    ok = dets:insert(
                           Db, {header, MaxSize, NewDigest, TailDigest})
            end
    end.
