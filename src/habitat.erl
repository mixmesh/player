-module(habitat).
-compile(export_all).

-define(PI, 3.141592).
-define(RADIANS_PER_DEGREE, (?PI / 180)).

-record(habitat,
        {f1 :: number(),
         f2 :: number(),
         r :: number()}).

test1() ->
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

test2() ->
    epx:start(),
    Width = 2048,
    Height = 2048,
    Pixels = epx:pixmap_create(Width, Height, argb),
    epx:pixmap_attach(Pixels),
    Background = epx:pixmap_create(Width, Height, argb),
    epx:pixmap_fill(Background, {255, 255, 255, 255}),
    Window = epx:window_create(
               0, 0, Width, Height, [button_press, button_release]),
    epx:window_attach(Window),
    Plot = fun(X, Y) ->
                   SafeX = window_wrap(X, Width),
                   SafeY = window_wrap(Y, Height),
                   %%io:format("3: ~p\n", [{X, Y}]),
                   epx:draw_ellipse(Background, SafeX, SafeY, 2, 2),
                   draw_ellipse(
                     Background, SafeX, SafeY, SafeX+50, SafeY + 50, 40),
                   %%epx:pixmap_put_pixel(Background, SafeX, SafeY, black),
                   update_window(Width, Height, Window, Pixels, Background),
                   {SafeX, SafeY}
           end,
    iterate(Window,
            fun() -> noise(0.05) end,
            fun() -> noise(0.05) end,
            Width / 2, Height / 2, Plot).

window_wrap(Value, Limit) when Value > Limit -> 0;
window_wrap(Value, Limit) when Value < 0 -> Limit;
window_wrap(Value, _Limit) -> Value.

iterate(Window, NextXDelta, NextYDelta, X, Y, Plot) ->
    {XDelta, EvenNextXDelta} = NextXDelta(),
    {YDelta, EvenNextYDelta} = NextYDelta(),
    NewX = X + (XDelta * 8 - 4),
    NewY = Y + (YDelta * 8 - 4),
    {SafeX, SafeY} = Plot(NewX , NewY),
    case is_window_closed(Window, 0) of
        true ->
            ok;
        false ->
            %%timer:sleep(100),
            iterate(Window, EvenNextXDelta, EvenNextYDelta, SafeX, SafeY, Plot)
    end.

test3() ->
    epx:start(),
    Width = 2048,
    Height = 2048,
    Pixels = epx:pixmap_create(Width, Height, argb),
    epx:pixmap_attach(Pixels),
    Background = epx:pixmap_create(Width, Height, argb),
    epx:pixmap_fill(Background, {255, 255, 255, 255}),
    Window = epx:window_create(
               0, 0, Width, Height, [button_press, button_release]),
    epx:window_attach(Window),
    draw_ellipse(Background, 100, 200, 200, 300, 200),
    update_window(Width, Height, Window, Pixels, Background),
    is_window_closed(Window, infinity).

%% https://stackoverflow.com/questions/11944767/draw-an-ellipse-based-on-its-foci/11947391#11947391

draw_ellipse(Pixmap, X1, Y1, X2, Y2, K) ->
    draw_ellipse(Pixmap, X1, Y1, X2, Y2, K, 2 * ?PI, ?PI / 5, not_set, 0).

draw_ellipse(Pixmap, X1, Y1, X2, Y2, K, Stop, Step, Last, T)
  when T > Stop ->
    draw_ellipse(Pixmap, X1, Y1, X2, Y2, K, Stop, Step, {stop, Last}, Stop);
draw_ellipse(Pixmap, X1, Y1, X2, Y2, K, Stop, Step, Last, T) ->
    %% Major axis
    A = K / 2.0, 
    %% Coordinates of the center
    Xc = (X1 + X2) / 2.0,
    Yc = (Y1 + Y2) / 2.0,
    %% Distance of the foci to the center
    Dc = math:sqrt(math:pow(X1 - X2, 2) + math:pow(Y1 - Y2, 2)) / 2,
    %% Minor axis
    B = math:sqrt(abs(math:pow(A, 2) - math:pow(Dc, 2))),
    Phi = math:atan(abs(Y1 - Y2) / abs(X1 - X2)),
    Xt = Xc + A * math:cos(T) * math:cos(Phi) - B * math:sin(T) * math:sin(Phi),
    Yt = Yc + A * math:cos(T) * math:sin(Phi) + B * math:sin(T) * math:cos(Phi),
    case Last of
        not_set ->
            draw_ellipse(Pixmap, X1, Y1, X2, Y2, K, Stop, Step, {Xt, Yt},
                         T + Step);
        {stop, {X, Y}} ->
            epx:draw_line(Pixmap, X, Y, Xt, Yt);
        {X, Y} ->
            epx:draw_line(Pixmap, X, Y, Xt, Yt),
            draw_ellipse(Pixmap, X1, Y1, X2, Y2, K, Stop, Step, {Xt, Yt},
                         T + Step)
    end.

is_window_closed(Window, Timeout) ->
    receive
        {epx_event, Window, close} ->
            epx:window_detach(Window),
            true
    after
        Timeout ->
            false
    end.

update_window(Width, Height, Window, Pixels, Background) ->
    epx:pixmap_copy_to(Background, Pixels),
    epx:pixmap_draw(Pixels, Window, 0, 0, 0, 0, Width, Height).

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
    {new_f1(L, Alpha, F1Old), new_f2(L, Alpha, Beta, F2Old)}.

d({X1, Y1}, {X2, Y2}) ->
    math:sqrt(math:pow(X2 - X1, 2) + math:pow(Y2 - Y1, 2)).

new_f1({X, Y}, Alpha, {XOld, YOld}) ->
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

%%
%% Perlin noise
%%

%% https://en.wikipedia.org/wiki/Perlin_noise
noise(Step) ->
    A = rand:uniform(),
    B = rand:uniform(),
    {A, fun() -> noise(Step, Step, A, B) end}.

noise(1, Step, _A, B) ->
    {B, fun() -> noise(Step, Step, B, rand:uniform()) end};
noise(Travel, Step, _A, B) when Travel > 1 ->
    NextB = rand:uniform(),
    InterpolatedB = smoothstep(B, NextB, 1 - Travel),
    {InterpolatedB, fun() -> noise(Step - (1 - Travel), Step, B, NextB) end};
noise(Travel, Step, A, B) ->
    InterpolatedB = smoothstep(A, B, Travel),
    {InterpolatedB, fun() -> noise(Travel + Step, Step, A, B) end}.

%% https://en.wikipedia.org/wiki/Smoothstep
smoothstep(A, B, W) ->
    (B - A) * (3.0 - W * 2.0) * W * W + A.

%%
%% Conversion from geodetic to ecef coordinates
%%

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
