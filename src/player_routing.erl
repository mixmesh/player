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
    RoutingInfo#routing_info{
      data = #location_routing{longitude = Longitude, latitude = Latitude}}.

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
                  data = #location_routing{
                            longitude = Longitude, latitude = Latitude}}) ->
    <<?ROUTING_LOCATION:8/unsigned-integer,
      Longitude/float,
      Latitude/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float>>.

%% Exported: header_to_info

header_to_info(<<?ROUTING_BLIND:8/unsigned-integer,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float>>) ->
    #routing_info{type = blind};
header_to_info(<<?ROUTING_LOCATION:8/unsigned-integer,
                 Longitude/float,
                 Latitude/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float,
                 ?NOT_USED/float>>) ->
    #routing_info{type = location,
                  data = #location_routing{
                            longitude = Longitude, latitude = Latitude}}.

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

distance(#routing_info{
            data = #location_routing{
                      longitude = Longitude1, latitude = Latitude1}},
         #routing_info{
            data = #location_routing{
                      longitude = Longitude2, latitude = Latitude2}}) ->
    math:sqrt(math:pow(Longitude2 - Longitude1, 2) +
                  math:pow(Latitude2 - Latitude1, 2)).
