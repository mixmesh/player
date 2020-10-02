-ifndef(PLAYER_SERV_HRL).
-define(PLAYER_SERV_HRL, true).

%% Spiridon parameters
-define(F, 0.2).
-define(K, 10).

-record(player,
        {name            :: binary(),
         player_serv_pid :: pid(),
         sync_address    :: inet:ip_address(),
         sync_port       :: inet:port_number(),
         smtp_address    :: inet:ip_address(),
         smtp_port       :: inet:port_number()}).

-endif.
