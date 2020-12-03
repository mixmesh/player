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
       {'sync-address',
        #json_type{
           name = ipaddress_port,
           typical = {{242,45,0,34}, 10000},
           reloadable = false}},
       {routing,
        [{type,
          #json_type{
             name = atom,
             info = "blind or location",
             typical = blind,
             convert =
                 fun(blind) -> blind;
                    (location) -> location;
                    (_) ->
                         throw(
                           {failed,
                            "Must be one of blind or location"})
                 end,
             reloadable = false}},
         {f,
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
             name = ipv4address_port,
             typical = {{242,45,0,34}, 20000},
             reloadable = false}},
         {'password-digest',
          #json_type{
              name = base64,
              typical = <<"7VWLYVsbr6YIsdxrZaCK+az9GeLTH/gCa3qKDNxht7e2WfsKN8aGVaKk5YBCdZ2FK07IJ+GvmstN/fPIH1djnA==">>,
              reloadable = false}}]},
       {'pop3-server',
        [{address,
          #json_type{
             name = ipv4address_port,
             typical = {{242,45,0,34}, 30000},
             reloadable = false}},
         {'password-digest',
          #json_type{
             name = base64,
             typical = <<"7VWLYVsbr6YIsdxrZaCK+az9GeLTH/gCa3qKDNxht7e2WfsKN8aGVaKk5YBCdZ2FK07IJ+GvmstN/fPIH1djnA==">>,
             reloadable = false}}]},
       {'http-server',
        [{address,
          #json_type{
             name = ipaddress_port,
             typical = {{242,45,0,34}, 8443},
             reloadable = false}},
         {'password',  %% should be stored encrypted via pin!
          #json_type {
             name = string,  %% db password
             typical = <<"password">>,
             reloadable = false}}]},
       {'pki-access-settings',
        [{mode,
          #json_type{
             name = atom,
             info = "global or local",
             typical = local,
             convert =
                 fun(global) -> global;
                    (local) -> local;
                    (_) ->
                         throw({failed,
                                <<"Must be one of global or local">>})
                 end,
             reloadable = false}},
         {global,
          [{'password',
            #json_type{
               name = string,
               typical = <<"smellyfeets">>,
               reloadable = false}},
           {access,
            #json_type{
               name = atom,
               info = "tor-only, tcp-only or tor-fallback-to-tcp",
               typical = tor_only,
               convert =
                   fun('tor-only') -> tor_only;
                      ('tcp-only') -> tcp_only;
                      ('tor-fallback-to-tcp') -> tor_fallback_to_tcp;
                      (_) ->
                           throw({failed,
                                  "Must be one of tor-only, tcp-only or tor-fallback-to-tcp"})
                   end,
               reloadable = false}},
           {'pki-server-tor-address',
            #json_type{
               name = hostname_port,
               typical = {"z2rev4qfooicn3z3.onion", 10000},
               reloadable = false}},
           {'pki-server-tcp-address',
            #json_type{
               name = ipv4address_port,
               typical = {"mother.tplinkdns.com", 10001},
               reloadable = false}}]}]}]}].
