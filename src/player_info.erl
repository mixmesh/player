%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    Debugging help - simulator encironment only
%%% @end
%%% Created : 12 Nov 2020 by Tony Rogvall <tony@rogvall.se>

-module(player_info).

-export([new/0, add/1, set/2, set/3, get/1, get/2, get/3]).
-export([nodis_i/1]).
-export([buffer_size/1, buffer_count/1]).

-define(TAB, player_info).

new() ->
    %% nym => #{key=>value}
    T = ets:new(?TAB, [public, named_table, {write_concurrency, true}]),
    %%io:format("player_info table created ~p\n", [ets:info(player_info)]),
    T.

add(Nym) ->
    ets:insert(?TAB, {nym(Nym), #{}}).

set(Name, Map) when is_map(Map) ->
    Nym = nym(Name),
    case ets:lookup(?TAB, Nym) of    
	[] ->
	    ets:insert(?TAB, {Nym,Map});
	[{_,OldMap}] ->
	    ets:insert(?TAB, maps:merge(OldMap,Map))
    end.
    
set(Name, Key, Value) ->
    Nym = nym(Name),
    case ets:lookup(?TAB, Nym) of
	[] ->
	    ets:insert(?TAB, {Nym, #{ Key => Value }});
	[{_,Map}] ->
	    ets:insert(?TAB, {Nym, Map#{ Key => Value }})
    end.

get(Name) ->
    Nym = nym(Name),
    case ets:lookup(?TAB, Nym) of
	[] -> #{};
	[{_,Map}] -> Map
    end.

get(Name, Key) ->
    Nym = nym(Name),
    case ets:lookup(?TAB, Nym) of
	[] -> error(badarg);
	[{_,Map}] -> maps:get(Key, Map)
    end.

get(Name, Key, Default) ->
    Nym = nym(Name),
    case ets:lookup(?TAB, Nym) of
	[] -> Default;
	[{_,Map}] -> maps:get(Key, Map, Default)
    end.

nym(Name) when is_atom(Name) ->
    atom_to_binary(Name);
nym(Name) when is_list(Name) ->
    list_to_binary(Name);
nym(Name) when is_binary(Name) ->
    Name.

%% utils

nodis_i(Name) ->
    nodis:i(get(Name, nodis_serv)).

buffer_size(Name) ->
    player_serv:buffer_size(get(Name, player_serv)).

buffer_count(Name) ->
    player_serv:buffer_count(get(Name, player_serv)).
