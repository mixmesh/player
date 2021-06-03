-module(player_schema).
-export([get/0]).

-include_lib("apptools/include/config_schema.hrl").
-include_lib("apptools/include/shorthand.hrl").

get() ->
    [{player,
      [{enabled,
        #json_type{
           name = bool,
           typical = false,
           reloadable = false}},
       {nym,
        #json_type{
           name = string,
           typical = <<"johndoe">>,
           reloadable = false}},
       {routing,
        [{type,
          #json_type{
             name = atom,
             info = "blind or location",
             typical = blind,
             transform =
                 fun(blind) -> blind;
                    (location) -> location;
                    (_) ->
                         throw(
                           {failed,
                            "Must be one of blind or location"})
                 end,
             reloadable = false}},
         {'use-gps',
          #json_type{
             name = bool,
             typical = true,
             reloadable = false}},
         {longitude,
          #json_type{
             name = {float, -180.0, 180.0},
             typical = 0.0,
             reloadable = false}},
         {latitude,
          #json_type{
             name = {float, -90.0, 90.0},
             typical = 0.0,
             reloadable = false}}]},
       {'sync-server',
        [{address,
          #json_type{
             name = ip_address_port,
             typical = {{242,45,0,34}, 10000},
             reloadable = false}},
         {'buffer-size',
          #json_type{
             name = {integer, 100, 10000000},
             typical = 1000,
             reloadable = false}},
         {f,
          #json_type{
             name = {float, 0.0, 1.0},
             typical = 0.2,
             reloadable = false}},
         {k,
          #json_type{
             name = {integer, 1, 10000},
             typical = 10,
             reloadable = false}},
         {'public-key',
          #json_type{
             name = base64,
             typical = <<"BWFsaWNlxgDD8BleR0lZOyTVMuguqs9IE1E7SuWgsyyNNNp4vrrQZbpF8PSiEhju2dL3cMnc5ZFAoe41NQ4+C45r+Xwk9dpo3sn5Uwj+ETZw5nC/StW+YeAlApeCZVL126AcOhQPtgRNyajc84Qg0dM7K5UDic/81kb0EqkaZ1awtwUrmPs=">>,
             reloadable = false}},
         {'secret-key',
          #json_type{
             name = base64,
             typical = <<"JUitY4g+ezCu1VJ9G11RSnfvKqieoGb+C+Q+CH6f+6EWC/lu+YAey2g9iTcpf/xoa501SFfUTCG1cV16tU/o/VOd18/zE98F7Jd6e/2NeiM6yMrCQrbFnY/cugQPwbKw6jf8lnxiO1+kBdqX5a5Fgs7eTsChd44lJY1QeFM7/rNECWKmPonIY/NwD3mcA3iBpUwmD0RYGdEB6IXFc30xgR2avOAWd0e+5PMnyvVw//OC12vvkZAdtK4oL1gTfHoQ9B5YGILeFmZdScfrAMXaY7BkVqiCpIa+xK86dtqzf0Afa7G/vg3Lj8wf2CXhq0e4+wqXSqBuIVhLn9TxIPe1jfA5r4IfOqCMRqZKmbQD3ltxp7Ojt79leAOl2PARJFOd+XMlISNtJ4WcYXyboeRAzw==">>,
             reloadable = false}}]},
       {'smtp-server',
        [{address,
          #json_type{
             name = interface_port,
             typical = <<"pan0:465">>,
             reloadable = false}},
         {'password-digest',
          #json_type{
              name = base64,
              typical = <<"7VWLYVsbr6YIsdxrZaCK+az9GeLTH/gCa3qKDNxht7e2WfsKN8aGVaKk5YBCdZ2FK07IJ+GvmstN/fPIH1djnA==">>,
              reloadable = false}}]},
       {'pop3-server',
        [{address,
          #json_type{
             name = interface_port,
             typical = <<"pan0:465">>,
             reloadable = false}},
         {'password-digest',
          #json_type{
             name = base64,
             typical = <<"7VWLYVsbr6YIsdxrZaCK+az9GeLTH/gCa3qKDNxht7e2WfsKN8aGVaKk5YBCdZ2FK07IJ+GvmstN/fPIH1djnA==">>,
             reloadable = false}}]},
       {'http-server',
        [{address,
          [#json_type{
              name = interface_port,
              typical = <<"pan0:443">>,
              reloadable = false}]},
         {'password', %% should be stored encrypted via pin!
          #json_type {
             name = string,  %% db password
             typical = <<"password">>,
             reloadable = false}}]},
       {'keydir-access-settings',
        [{mode,
          #json_type{
             name = atom,
             info = "local or service",
             typical = local,
             transform =
                 fun(local) -> local;
                    (service) -> service;
                    (_) ->
                         throw({failed,
                                <<"Must be one of local or service">>})
                 end,
             reloadable = false}},
         {service,
          [{'password',
            #json_type{
               name = string,
               typical = <<"smellyfeets">>,
               reloadable = false}},
           {address,
            #json_type{
               name = ip4_address_port,
               typical = {"keydir.mixmesh.se", 4436},
               reloadable = false}}]}]}]}].
