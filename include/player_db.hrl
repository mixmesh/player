-ifndef(PLAYER_DB_HRL).
-define(PLAYER_DB_HRL, true).

-include_lib("player/include/player_serv.hrl").

-record(db_player,
        {name                  :: binary(),
         x = not_set           :: number() | not_set,
         y = not_set           :: number() | not_set,
         buffer_size = not_set :: integer() | not_set,
         neighbours = not_set  :: [#player{}] | not_set,
         is_zombie = not_set   :: boolean() | not_set,
         pick_mode = not_set   :: player_serv:pick_mode() | not_set}).

-endif.
