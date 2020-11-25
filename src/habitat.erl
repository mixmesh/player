-module(habitat).
-compile(export_all).

-define(PI, 3.141592).
-define(RADIANS_PER_DEGREE, (?PI / 180)).

-record(habitat,
        {f1 :: number(),
         f2 :: number(),
         r :: number()}).

t1() ->
    



test() ->
    Latitude = 51.509865,
    Longitude = -0.118092,
    {X, Y, _Z} = geodetic_to_ecef_coordinates(Latitude, Longitude, 0),
    L = {X, Y}, %% Initial location
    H = init_habitat(L),
    NewL = {X + 12, Y + 100},
    W = 3600 / 2, % Updates per hour
    T = 1,  %% Time to consider in hours
    Alpha = calculate_alpha(W, T),
    Beta = 60,
    {H, update_habitat(H, NewL, Alpha, Beta)}.

%% Section 3.3.1
init_habitat(L0) ->
    #habitat{f1 = L0, f2 = L0, r = 0}.

update_habitat(H, NewL, Alpha, Beta) ->
    {F1, F2} = update_focal_points(H, NewL, Alpha, Beta),
    R = update_radius(H#habitat.r, NewL, Alpha, F1, F2),
    #habitat{f1 = F1, f2 = F2, r = R}.

%% Section 3.3.2
update_focal_points(#habitat{f1 = F1, f2 = F2, r = 0}, L, Alpha, Beta) ->
    {F1Old, F2Old} =
        case {d(F1, L), d(F2, L)} of
            {F1LDistance, F2LDistance} when F1LDistance < F2LDistance ->
                {F1, F2};
            _ ->
                {F2, F1}
        end,
    {new_f1(L, Alpha, Beta, F1Old), new_f2(L, Alpha, Beta, F2Old)}.

d({X1, Y1}, {X2, Y2}) ->
    math:sqrt(math:pow(X2 - X1, 2) + math:pow(Y2 - Y1, 2)).

new_f1({X, Y}, Alpha, Beta, {XOld, YOld}) ->
    {X * Alpha + XOld * (1 - Alpha), Y * Alpha + YOld * (1 - Alpha)}.

new_f2({X, Y}, Alpha, Beta, {XOld, YOld}) ->
    AlphaBetaQuota = Alpha / Beta,
    {X * AlphaBetaQuota + XOld * (1 - AlphaBetaQuota),
     Y * AlphaBetaQuota + YOld * (1 - AlphaBetaQuota)}.

%% Section 3.3.3
update_radius(OldR, L, Alpha, F1, F2) ->
    (d(L, F1) + d(L, F2)) * Alpha + OldR * (1 - Alpha).

%% Section 3.3.4
calculate_alpha(W, T) ->
    2 / (T * W + 1).

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
    N = A2 / math:sqrt(math:pow(CLatitude, 2) * A2 + math:pow(SLatitude, 2) * B2),
    X = (N + H) * CLatitude * CLongitude, 
    Y = (N + H) * CLatitude * SLongitude, 
    Z  = (B2 / A2 * N + H) * SLatitude,
    {X, Y, Z}.
