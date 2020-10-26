-ifndef(PLAYER_SYNC_SERV_HRL).
-define(PLAYER_SYNC_SERV_HRL, true).

-include_lib("elgamal/include/elgamal.hrl").

-record(player_sync_serv_options,
        {simulated = false :: boolean(),
	 sync_address :: undefined | {inet:ip_address(), inet:port_number()},
	 ip_address = {127, 0, 0, 1} :: inet:ip_address(),
         recv_timeout = 150000 :: integer(),
         connect_timeout = 600000 :: integer(),
         f :: float(),
         keys = not_set :: {#pk{}, #sk{}} | not_set}).

-endif.
