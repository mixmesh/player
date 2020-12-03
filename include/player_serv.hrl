-ifndef(PLAYER_SERV_HRL).
-define(PLAYER_SERV_HRL, true).

-include_lib("elgamal/include/elgamal.hrl").

%% Spiridon parameters
-define(F, 0.2).
-define(K, 10).

-record(player,
        {nym :: binary(),
         player_serv_pid :: pid(),
         nodis_serv_pid :: pid(),
         sync_address :: {inet:ip4_address(), inet:port_number()},
         smtp_address :: {inet:ip4_address(), inet:port_number()}}).

-record(db_player,
        {nym :: binary(),
         x = not_set :: number() | not_set,
         y = not_set :: number() | not_set,
         buffer_size = not_set :: integer() | not_set,
	 count = not_set :: integer() | not_set,
         neighbours = not_set :: [#player{}] | not_set,
         is_zombie = not_set :: boolean() | not_set,
         pick_mode = not_set :: player_serv:pick_mode() | not_set}).

-record(simulated_player_serv_config,
        {players_dir :: binary(),
         nym :: binary(),
         sync_address :: {inet:ip_address(), inet:port_number()},
         routing_type :: player_routing:routing_type(),
         keys :: {#pk{}, #sk{}},
         f :: float(),
         get_location_generator :: function(),
         degrees_to_meters :: function(),
         smtp_address :: {inet:ip4_address(), inet:port_number()},
         smtp_password_digest :: binary(),
         pop3_address :: {inet:ip4_address(), inet:port_number()},
         pop3_password_digest :: binary(),
         http_address :: {inet:ip4_address(), inet:port_number()},
         http_password :: binary(),
         pki_mode :: local | {global, pki_network_client:pki_access()}}).

-endif.
