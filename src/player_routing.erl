-module(player_routing).
-export([update_info/3, info_to_header/1, header_to_info/1,
         is_neighbour_more_suitable/3]).
-export_type([routing_type/0]).

-include_lib("apptools/include/log.hrl").
-include("player_routing.hrl").

-define(PI, 3.141592).
-define(RADIANS_PER_DEGREE, (?PI / 180)).
-define(NOT_USED, 0).

-type routing_type() :: blind | location.

%% Exported: update_info

update_info(#routing_info{type = blind} = RoutingInfo, _Longitude, _Latitude) ->
    RoutingInfo;
update_info(#routing_info{type = location} = RoutingInfo, none, none) ->
    RoutingInfo;
update_info(#routing_info{type = location} = RoutingInfo, Longitude,
            Latitude) ->
    {X, Y, _Z} = geodetic_to_ecef_coordinates(Latitude, Longitude, 0),
    RoutingInfo#routing_info{data = #location_routing{x = X, y = Y}}.

%% Exported: info_header

info_to_header(blind) ->
    <<?ROUTING_BLIND:8/unsigned-integer,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float>>;
info_to_header(#routing_info{type = blind}) ->
    <<?ROUTING_BLIND:8/unsigned-integer,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float>>;
info_to_header(#routing_info{type = location, data = none}) ->
    <<?ROUTING_BLIND:8/unsigned-integer,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float>>;
info_to_header(#routing_info{
                  type = location,
                  data = #location_routing{x = X, y = Y}}) ->
    <<?ROUTING_LOCATION:8/unsigned-integer,
      X/float,
      Y/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float>>.

%% https://en.m.wikipedia.org/wiki/Geographic_coordinate_conversion#From_geodetic_to_ECEF_coordinates 
%% https://en.m.wikipedia.org/wiki/Geodetic_datum#World_Geodetic_System_1984_(WGS_84)

geodetic_to_ecef_coordinates(Latitude, Longitude, H) ->
    CLatitude = math:cos(Latitude * ?RADIANS_PER_DEGREE),
    SLatitude = math:sin(Latitude *  ?RADIANS_PER_DEGREE),
    CLongitude = math:cos(Longitude * ?RADIANS_PER_DEGREE),
    SLongitude = math:sin(Longitude  * ?RADIANS_PER_DEGREE),
    %% Semi-major axis
    A = 6378137.0,
    A2 = math:pow(A, 2),
    %% Semi-minor axis
    B = 6356752.3142,
    B2 = math:pow(B, 2),
    %% Prime vertical radius of curvature
    N = A2 / math:sqrt(
               math:pow(CLatitude, 2) * A2 + math:pow(SLatitude, 2) * B2),
    X = (N + H) * CLatitude * CLongitude, 
    Y = (N + H) * CLatitude * SLongitude, 
    Z  = (B2 / A2 * N + H) * SLatitude,
    {X, Y, Z}.

%% Exported: header_to_info

header_to_info(<<?ROUTING_BLIND:8/unsigned-integer,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float>>) ->
    #routing_info{type = blind};
header_to_info(<<?ROUTING_LOCATION:8/unsigned-integer,
                 X/float,
                 Y/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float>>) ->
    #routing_info{type = location,
                  data = #location_routing{x = X, y = Y}}.

%% Exported: is_neighbour_more_suitable

is_neighbour_more_suitable(#routing_info{type = blind}, _RoutingInfo,
                           _MessageRoutingInfo) ->
    blind;
is_neighbour_more_suitable(_NeighbourRoutingInfo, #routing_info{type = blind},
                           _MessageRoutingInfo) ->
    blind;
is_neighbour_more_suitable(_NeighbourRoutingInfo, _RoutingInfo,
                           #routing_info{type = blind}) ->
    blind;
is_neighbour_more_suitable(#routing_info{type = location, data = none},
                           _RoutingInfo, _MessageRoutingInfo) ->
    blind;
is_neighbour_more_suitable(_NeighbourRouting,
                           #routing_info{type = location, data = none},
                           _MessageRoutingInfo) ->
    blind;
is_neighbour_more_suitable(NeighbourRoutingInfo, RoutingInfo,
                           MessageRoutingInfo) ->
    distance(NeighbourRoutingInfo, MessageRoutingInfo) /
        distance(RoutingInfo, MessageRoutingInfo).

distance(#routing_info{data = #location_routing{x = X1, y = Y1}},
         #routing_info{data = #location_routing{x = X2, y = Y2}}) ->
    math:sqrt(math:pow(X2 - X1, 2) + math:pow(Y2 - Y1, 2)).
