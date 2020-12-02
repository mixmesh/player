-ifndef(PLAYER_ROUTING_HRL).
-define(PLAYER_ROUTING_HRL, true).

-include_lib("elgamal/include/elgamal.hrl").

%% Routing types
-define(ROUTING_BLIND, 0).
-define(ROUTING_LOCATION, 1).
-define(ROUTING_HABITAT, 2).

-define(ROUTING_HEADER_SIZE, (1 + 5 * 8)). %% Routing type byte + 5 floats
-define(ROUTING_HEADER_AND_MESSAGE_SIZE,
        (?ROUTING_HEADER_SIZE + ?ENCODED_SIZE)).

-endif.
