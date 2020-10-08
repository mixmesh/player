-ifndef(PLAYER_SERV_HRL).
-define(PLAYER_SERV_HRL, true).

%% Spiridon parameters
-define(F, 0.2).
-define(K, 10).

-record(player,
        {name            :: binary(),
         player_serv_pid :: pid(),
         nodis_serv_pid  :: pid(),
         sync_ip_address :: inet:ip4_address(),
         sync_port       :: inet:port_number(),
         smtp_ip_address :: inet:ip4_address(),
         smtp_port       :: inet:port_number()}).

-endif.
