-ifndef(PLAYER_SERV_HRL).
-define(PLAYER_SERV_HRL, true).

%% Spiridon parameters
-define(F, 0.2).
-define(K, 10).

-record(player,
        {name            :: binary(),
         player_serv_pid :: pid(),
         nodis_serv_pid  :: pid(),
         sync_address    :: {inet:ip4_address(), inet:port_number()},
         smtp_address    :: {inet:ip4_address(), inet:port_number()}}).

-record(db_player,
        {name                  :: binary(),
         x = not_set           :: number() | not_set,
         y = not_set           :: number() | not_set,
         buffer_size = not_set :: integer() | not_set,
         neighbours = not_set  :: [#player{}] | not_set,
         is_zombie = not_set   :: boolean() | not_set,
         pick_mode = not_set   :: player_serv:pick_mode() | not_set}).

-endif.
