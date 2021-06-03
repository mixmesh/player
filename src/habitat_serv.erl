-module(habitat_serv).
-export([start_link/2, stop/1]).
-export([message_handler/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/shorthand.hrl").

-record(habitat,
        {f1 :: {number(), number()},
         f2 :: {number(), number()},
         r :: number()}).

-record(state,
        {parent :: pid(),
         nym :: binary(),
         longitude_topic :: binary(),
         latitude_topic :: binary(),
         longitude = {old, 0} :: {new | old, number()},
         latitude = {old, 0} :: {new | old, number()},
         alpha :: number(),
         beta :: number(),
         habitat = not_set :: #habitat{} | not_set,
         nodis_serv_pid = not_set :: pid() | not_set,
         simulated :: boolean()}).

%%
%% Exported: start_link
%%

start_link(Nym, Simulated) ->
    ?spawn_server(fun(Parent) -> init(Parent, Nym, Simulated) end,
                  fun initial_message_handler/1).

initial_message_handler(#state{simulated = Simulated} = State) ->
    receive
        {neighbour_workers, NeighbourWorkers} ->
            case Simulated of
                true ->
                    [NodisServPid] =
                        supervisor_helper:get_selected_worker_pids(
                          [nodis_serv], NeighbourWorkers);
                false ->
                    NodisServPid = whereis(nodis_serv)
            end,
            {swap_message_handler, fun ?MODULE:message_handler/1,
             State#state{nodis_serv_pid = NodisServPid}}
    end.

%%
%% Exported: stop
%%

stop(Pid) ->
    serv:call(Pid, stop).

%%
%% Server
%%

init(Parent, Nym, Simulated) ->
    %% A number of hardwired constants introduced by
    %% https://github.com/joagre/papers/blob/main/S%C3%A1nchez-Carmona-2016.pdf.
    %% The update frequency refers to the number of location updates per second.
    %% NOTE: The update frequency *must* be exactly the same as being used by
    %% the simulations in simulator/src/{simulator_location,mesh}.erl
    %% and by the GPS server in pimesh/src/pimesh_gps_serv.erl. Let
    %% this value be 1Hz or you will probably be sorry.
    UpdateFrequency = 1,
    W = UpdateFrequency * 3600, % Updates per hour
    T = 0.1,  %% Time to consider in hours (0.1 = 6 minutes)
    Alpha = calculate_alpha(W, T),
    Beta = 60,
    init(Parent, Nym, Simulated, Alpha, Beta).

init(Parent, Nym, Simulated, Alpha, Beta) ->
    case Simulated of
        true ->
            TopicPrefix =
                ?l2b([<<"mixmesh.routing.simulated.">>, Nym, <<".location">>]),
            LongitudeTopic = ?l2b([TopicPrefix, <<".longitude">>]),
            LatitudeTopic = ?l2b([TopicPrefix, <<".latitude">>]);
        false ->
            LongitudeTopic = <<"mixmesh.routing.hw.location.longitude">>,
            LatitudeTopic = <<"mixmesh.routing.hw.location.latitude">>
    end,
    true = xbus:sub(LongitudeTopic),
    true = xbus:sub(LatitudeTopic),
    ?daemon_log_tag_fmt(
       system, "Habitat server for ~s has been started", [Nym]),
    {ok, #state{parent = Parent,
                nym = Nym,
                longitude_topic = LongitudeTopic,
                latitude_topic = LatitudeTopic,
                alpha = Alpha,
                beta = Beta,
                simulated = Simulated}}.

message_handler(#state{parent = Parent,
                       longitude_topic = LongitudeTopic,
                       latitude_topic = LatitudeTopic,
                       longitude = {OldOrNewLongitude, Longitude},
                       latitude = {OldOrNewLatitude, Latitude},
                       alpha = Alpha,
                       beta = Beta,
                       habitat = Habitat,
                       nodis_serv_pid = NodisServPid} = State) ->
    receive
        {call, From, stop} ->
            {stop, From, ok};
	{xbus, LongitudeTopic, #{value := NewLongitude}} ->
            case OldOrNewLatitude of
                new ->
                    UpdatedHabitat =
                        update_habitat(
                          Habitat, {NewLongitude, Latitude}, Alpha, Beta),
                    #habitat{f1 = F1, f2 = F2, r = R} = UpdatedHabitat,
                    ok = nodis_serv:set_node_habitat(NodisServPid, {F1, F2, R}),
                    ?dbg_log({updated_habitat, Habitat, UpdatedHabitat}),
                    {noreply, State#state{
                                longitude = {old, NewLongitude},
                                latitude = {old, Latitude},
                                habitat = UpdatedHabitat}};
                old ->
                    {noreply, State#state{longitude = {new, NewLongitude}}}
            end;
	{xbus, LatitudeTopic, #{value := NewLatitude}} ->
            case OldOrNewLongitude of
                new ->
                    UpdatedHabitat =
                        update_habitat(
                          Habitat, {Longitude, NewLatitude}, Alpha, Beta),
                    #habitat{f1 = F1, f2 = F2, r = R} = UpdatedHabitat,
                    ok = nodis_serv:set_node_habitat(NodisServPid, {F1, F2, R}),
                    ?dbg_log({updated_habitat, Habitat, UpdatedHabitat}),
                    {noreply, State#state{
                                longitude = {old, Longitude},
                                latitude = {old, NewLatitude},
                                habitat = UpdatedHabitat}};
                old ->
                    {noreply, State#state{latitude = {new, NewLatitude}}}
            end;
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            exit(Reason);
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

%%
%% Habitat calculations
%%
%% Section references below refers to the sections in
%% https://github.com/joagre/papers/blob/main/S%C3%A1nchez-Carmona-2016.pdf
%%

%% Section 3.3.1
init_habitat(L0) ->
    #habitat{f1 = L0, f2 = L0, r = 0}.

update_habitat(not_set, L0, _Alpha, _Beta) ->
    init_habitat(L0);
update_habitat(Habitat, NewL, Alpha, Beta) ->
    {F1, F2} = update_focal_points(Habitat, NewL, Alpha, Beta),
    R = update_radius(Habitat#habitat.r, NewL, Alpha, F1, F2),
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

d({Longitude1, Latitude1}, {Longitude2, Latitude2}) ->
    math:sqrt(math:pow(Longitude2 - Longitude1, 2) +
                  math:pow(Latitude2 - Latitude1, 2)).

new_f1({Longitude, Latitude}, Alpha, {LongitudeOld, LatitudeOld}) ->
    {Longitude * Alpha + LongitudeOld * (1 - Alpha),
     Latitude * Alpha + LatitudeOld * (1 - Alpha)}.

new_f2({Longitude, Latitude}, Alpha, Beta, {LongitudeOld, LatitudeOld}) ->
    AlphaBetaQuota = Alpha / Beta,
    {Longitude * AlphaBetaQuota + LongitudeOld * (1 - AlphaBetaQuota),
     Latitude * AlphaBetaQuota + LatitudeOld * (1 - AlphaBetaQuota)}.

%% Section 3.3.3
update_radius(OldR, L, Alpha, F1, F2) ->
    (d(L, F1) + d(L, F2)) * Alpha + OldR * (1 - Alpha).

%% Section 3.3.4
calculate_alpha(W, T) ->
    2 / (T * W + 1).
