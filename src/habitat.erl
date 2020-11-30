-module(habitat).
-export([demo/0]).
-export([thabitat/0, tellipse/0]). % tests

-define(PI, 3.141592).
-define(RADIANS_PER_DEGREE, (?PI / 180)).
-define(PIXEL_FORMAT, rgb).
%% https://lospec.com/palette-list/cingi-25
-define(BACKGROUND_COLOR, {232, 236, 242}).
-define(HABITAT_COLOR, {31, 37, 54}).
-define(PLAYER_COLOR0, {255, 0, 0}).
-define(PLAYER_COLOR1, {255, 0, 255}).
-define(PLAYER_COLOR2, {0, 255, 255}).
-define(PLAYER_COLOR3, {128, 0, 128}).
-define(PLAYER_COLOR4, {0, 255, 0}).
-define(MAX_SAVED_LOCATIONS, 200).

-record(habitat,
        {f1 :: {number(), number()},
         f2 :: {number(), number()},
         r :: number()}).

demo() ->
    application:ensure_all_started(epx),
    Width = 1037,
    Height = 851,
    Pixmap = epx:pixmap_create(Width, Height, ?PIXEL_FORMAT),
    epx:pixmap_attach(Pixmap),
    Filename = filename:join([code:priv_dir(player), "small-area-51.xpm"]),
    {ok, BackgroundImage} = epx_image:load(Filename),
    Background = hd(epx_image:pixmaps(BackgroundImage)),
    Canvas = epx:pixmap_create(Width, Height, ?PIXEL_FORMAT),
    epx:pixmap_copy_to(Background, Canvas),
    Window = epx:window_create(
               0, 0, Width, Height, [button_press, button_release]),
    epx:window_attach(Window),
    Plot = fun(clear) ->
                   epx:pixmap_copy_to(Background, Canvas);
              (update_window) ->
                   update_window(Width, Height, Window, Pixmap, Canvas);
              ({{X, Y}, Color, SavedLocations}) ->
                   SafeX = window_fence(X, Width),
                   SafeY = window_fence(Y, Height),
                   epx_gc:set_fill_color(Color),
                   epx:draw_rectangle(Canvas, SafeX - 2, SafeY - 2, 4, 4),
                   epx_gc:set_foreground_color(Color),
                   (fun F([{X1, Y1}, {X2, Y2}|Rest]) ->
                            epx:draw_line(Canvas, X1, Y1, X2, Y2),
                            F([{X2, Y2}|Rest]);
                        F(_) ->
                            ok
                    end)([{SafeX, SafeY}|SavedLocations]),
                   {SafeX, SafeY};
              (#habitat{r = 0}) ->
                   skip;
              (#habitat{f1 = {F1X, F1Y}, f2 = {F2X, F2Y}, r = R}) ->
                   epx_gc:set_foreground_color(?HABITAT_COLOR),
                   draw_ellipse(Canvas, F1X, F1Y, F2X, F2Y, R)
           end,
    DeltaScale = 10,
    W = 1800, % Updates per hour
    T = 0.1,  %% Time to consider in hours 
    SpeedFactor = 8,
    Delay = trunc(3600 / W * 1000 / SpeedFactor),
    Alpha = calculate_alpha(W, T),
    Beta = 60,
    Width4 = Width / 4,
    Height4 = Height / 4,
    iterate(Window,
            [{fun() -> noise(0.05) end,
              fun() -> noise(0.05) end,
              Width4, Height4, ?PLAYER_COLOR0, not_set, []},
             {fun() -> noise(0.05) end,
              fun() -> noise(0.05) end,
              Width4 * 3, Height4, ?PLAYER_COLOR1, not_set, []},
             {fun() -> noise(0.05) end,
              fun() -> noise(0.05) end,
              Width4 * 2, Height4 * 2, ?PLAYER_COLOR2, not_set, []},
             {fun() -> noise(0.05) end,
              fun() -> noise(0.05) end,
              Width4, Height4 * 3, ?PLAYER_COLOR3, not_set, []},
             {fun() -> noise(0.05) end,
              fun() -> noise(0.05) end,
              Width4 * 3, Height4 * 3, ?PLAYER_COLOR4, not_set, []}],
            DeltaScale, Delay, Alpha, Beta, Plot).

window_fence(Value, Limit) when Value > Limit ->
    Limit - Limit / 80;
window_fence(Value, Limit) when Value < 0 ->
    Limit / 80;
window_fence(Value, _Limit) ->
    Value.

iterate(Window, Players, DeltaScale, Delay, Alpha, Beta, Plot) ->
    Plot(clear),
    UpdatedPlayers =
        lists:foldl(
          fun({NextXDelta, NextYDelta, X, Y, Color, Habitat, SavedLocations},
              Acc) ->
                  {XDelta, EvenNextXDelta} = NextXDelta(),
                  {YDelta, EvenNextYDelta} = NextYDelta(),
                  NewX = X + (XDelta * DeltaScale - DeltaScale / 2),
                  NewY = Y + (YDelta * DeltaScale - DeltaScale / 2),
                  {SafeX, SafeY} = Plot({{NewX , NewY}, Color, SavedLocations}),
                  UpdatedHabitat =
                      case Habitat of
                          not_set ->
                              init_habitat({SafeX, SafeY});
                          _ ->
                              update_habitat(Habitat, {SafeX, SafeY}, Alpha,
                                             Beta)
                      end,
                  Plot(UpdatedHabitat),
                  UpdatedSavedLocations =
                      case length(SavedLocations) > ?MAX_SAVED_LOCATIONS of
                          true ->
                              [{SafeX, SafeY}|lists:droplast(SavedLocations)];
                          false ->
                              [{SafeX, SafeY}|SavedLocations]
                      end,
                  [{EvenNextXDelta, EvenNextYDelta, SafeX, SafeY, Color,
                    UpdatedHabitat, UpdatedSavedLocations}|Acc]
          end, [], Players),
    Plot(update_window),
    case is_window_closed(Window, 0) of
        true ->
            ok;
        false ->
            timer:sleep(Delay),
            iterate(Window, UpdatedPlayers, DeltaScale, Delay, Alpha, Beta,
                    Plot)
    end.

%% https://stackoverflow.com/questions/11944767/draw-an-ellipse-based-on-its-foci/11947391#11947391
draw_ellipse(Canvas, X1, Y1, X2, Y2, K) ->
    draw_ellipse(Canvas, X1, Y1, X2, Y2, K, 2 * ?PI, ?PI / 20, not_set, 0).

draw_ellipse(Canvas, X1, Y1, X2, Y2, K, Stop, Step, Last, T)
  when T > Stop ->
    draw_ellipse(Canvas, X1, Y1, X2, Y2, K, Stop, Step, {stop, Last}, Stop);
draw_ellipse(Canvas, X1, Y1, X2, Y2, K, Stop, Step, Last, T) ->
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
            draw_ellipse(Canvas, X1, Y1, X2, Y2, K, Stop, Step, {Xt, Yt},
                         T + Step);
        {stop, {X, Y}} ->
            epx:draw_line(Canvas, X, Y, Xt, Yt);
        {X, Y} ->
            epx:draw_line(Canvas, X, Y, Xt, Yt),
            draw_ellipse(Canvas, X1, Y1, X2, Y2, K, Stop, Step, {Xt, Yt},
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

update_window(Width, Height, Window, Pixmap, Canvas) ->
    epx:pixmap_copy_to(Canvas, Pixmap),
    epx:pixmap_draw(Pixmap, Window, 0, 0, 0, 0, Width, Height).

%% Section 3.3.1
init_habitat(L0) ->
    #habitat{f1 = L0, f2 = L0, r = 0}.

update_habitat(H, NewL, Alpha, Beta) ->
    {F1, F2} = update_focal_points(H, NewL, Alpha, Beta),
    R = update_radius(H#habitat.r, NewL, Alpha, F1, F2),
    #habitat{f1 = F1, f2 = F2, r = R}.

%% Section 3.3.2
update_focal_points(#habitat{f1 = F1, f2 = F2, r = _R}, L, Alpha, Beta) ->
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

noise(1.0, Step, _A, B) ->
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

%%
%% Tests
%%

thabitat() ->
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

tellipse() ->
    epx:start(),
    Width = 2048,
    Height = 2048,
    Pixmap = epx:pixmap_create(Width, Height, argb),
    epx:pixmap_attach(Pixmap),
    Canvas = epx:pixmap_create(Width, Height, argb),
    epx:pixmap_fill(Canvas, {255, 255, 255, 255}),
    Window = epx:window_create(
               0, 0, Width, Height, [button_press, button_release]),
    epx:window_attach(Window),
    draw_ellipse(Canvas, 100, 200, 200, 300, 200),
    update_window(Width, Height, Window, Pixmap, Canvas),
    is_window_closed(Window, infinity).
