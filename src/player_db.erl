-module(player_db).
-export([new/0, lookup/1, add/3, update/1, foldl/2]).

-include_lib("player/include/player_serv.hrl").

%% Exported: new

new() ->
    ?MODULE == ets:new(?MODULE,
                       [public, named_table, {keypos, #db_player.nym},
                        {write_concurrency, true}]).

%% Exported: lookup

lookup(Nym) ->
    ets:lookup(?MODULE, Nym).

%% Exported: add

add(Nym, X, Y) ->
    ets:insert(?MODULE,
               #db_player{nym = Nym,
                          x = X,
                          y = Y,
                          buffer_size = 0,
                          neighbours = [],
                          is_zombie = false,
                          pick_mode = is_nothing}).

%% Exported: update

update(#db_player{nym = Nym,
                  x = X,
                  y = Y,
                  buffer_size = BufferSize,
                  neighbours = Neighbours,
                  is_zombie = IsZombie,
                  pick_mode = PickMode}) ->
    case lookup(Nym) of
        [DbPlayer] ->
            ets:insert(
              ?MODULE,
              DbPlayer#db_player{
                x = get_value(X, DbPlayer#db_player.x),
                y = get_value(Y, DbPlayer#db_player.y),
                buffer_size = get_value(BufferSize,
                                        DbPlayer#db_player.buffer_size),
                neighbours = get_value(Neighbours,
                                       DbPlayer#db_player.neighbours),
                is_zombie = get_value(IsZombie,
                                      DbPlayer#db_player.is_zombie),
                pick_mode = get_value(PickMode,
                                      DbPlayer#db_player.pick_mode)});
        [] ->
            true
    end.

get_value(not_set, DefaultValue) ->
    DefaultValue;
get_value(Value, _DefaultValue) ->
    Value.

%% Exported: foldl

foldl(Fun, Acc) ->
    ets:foldl(Fun, Acc, ?MODULE).
