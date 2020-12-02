-module(player_routing).
-export([make_header/1, make_header/3]).

-include("player_routing.hrl").

-define(PI, 3.141592).
-define(RADIANS_PER_DEGREE, (?PI / 180)).
-define(NOT_USED, 0).

%% Exported: make_header

make_header(blind) ->
    <<?ROUTING_BLIND:8/unsigned-integer,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float>>.

make_header(location, none, none) ->
    <<?ROUTING_BLIND:8/unsigned-integer,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float,
      ?NOT_USED/float>>;
make_header(location, Longitude, Latitude) ->
    {X, Y, _Z} = geodetic_to_ecef_coordinates(Latitude, Longitude, 0),
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
