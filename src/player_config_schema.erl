-module(player_config_schema).
-export([get/0]).

-include_lib("apptools/include/config_schema.hrl").

get() ->
    [{player,
      [{enabled,
        #json_type{
           name = bool,
           typical = false,
           reloadable = false}},
       {username,
        #json_type{
           name = string,
           typical = <<"johndoe">>,
           reloadable = false}},
       {password,
        #json_type{
           name = string,
           typical = <<"smellyfeets">>,
           reloadable = false}},
       {'sync-address',
        #json_type{
           name = ipv4address_port,
           typical = {{242,45,0,34}, 10000},
           reloadable = false}},
       {'temp-dir',
        #json_type{
           name = writable_directory,
           typical = <<"/var/obscrete/players/johndoe/smtp/temp">>,
           reloadable = false}},
       {spiridon,
        [{f,
          #json_type{
             name = {float, 0.0, 1.0},
             typical = 0.2,
             reloadable = false}},
         {k,
          #json_type{
             name = {integer, 1, 100},
             typical = 10,
             reloadable = false}},
         {'public-key',
          #json_type{
             name = base64,
             typical = <<"Zm9v">>,
             convert = fun(Binary) ->
                               belgamal:binary_to_public_key(Binary)
                       end,
             reloadable = false}},
         {'secret-key',
          #json_type{
             name = base64,
             typical = <<"Zm9v">>,
             convert = fun(Binary) ->
                               belgamal:binary_to_secret_key(Binary)
                       end,
             reloadable = false}}]},
       {maildrop,
        [{'spooler-dir',
          #json_type{
             name = writable_directory,
             typical = <<"/var/obscrete/players/johndoe/maildrop/spooler">>,
             reloadable = false}}]},
       {'smtp-proxy',
        [{address,
          #json_type{
             name = ipv4address_port,
             typical = {{242,45,0,34}, 20000},
             reloadable = false}}]},
       {'pop3-proxy',
        [{address,
          #json_type{
             name = ipv4address_port,
             typical = {{242,45,0,34}, 30000},
             reloadable = false}}]}]}].
