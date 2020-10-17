-ifndef(PLAYER_SERV_HRL).
-define(PLAYER_SERV_HRL, true).

-include_lib("elgamal/include/elgamal.hrl").

%% Spiridon parameters
-define(F, 0.2).
-define(K, 10).

-record(player,
        {name :: binary(),
         player_serv_pid :: pid(),
         nodis_serv_pid :: pid(),
         sync_address :: {inet:ip4_address(), inet:port_number()},
         smtp_address :: {inet:ip4_address(), inet:port_number()}}).

-record(db_player,
        {name :: binary(),
         x = not_set :: number() | not_set,
         y = not_set :: number() | not_set,
         buffer_size = not_set :: integer() | not_set,
         neighbours = not_set :: [#player{}] | not_set,
         is_zombie = not_set :: boolean() | not_set,
         pick_mode = not_set :: player_serv:pick_mode() | not_set}).

-record(simulated_player_serv_config,
        {name :: binary(),
         pki_password :: binary(),
         sync_address :: {inet:ip_address(), inet:port_number()},
         temp_dir :: binary(),
         buffer_dir :: binary(),
         keys :: {#pk{}, #sk{}},
         f :: float(),
         get_location_generator :: function(),
         degrees_to_meters :: function(),
         spooler_dir :: binary(),
         smtp_address :: {inet:ip4_address(), inet:port_number()},
         smtp_cert_filename :: binary(),
         smtp_password_digest :: binary(),
         pop3_address :: {inet:ip4_address(), inet:port_number()},
         pop3_cert_filename :: binary(),
         pop3_password_digest :: binary(),
         local_pki_server_data_dir :: binary(),
         pki_mode :: local | {global, pki_network_client:pki_access()}}).

-endif.
