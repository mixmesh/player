-module(player_interface).
-export([get_mail_ip_address/0, get_http_ip_address/0]).

-define(MAIL_IF_NAMES, ["pan0", "wlp37s0"]).
-define(HTTP_IF_NAMES, ["usb0", "pan0", "wlp37s0"]).

%% Exported: get_mail_ip_address

get_mail_ip_address() ->
    get_addr(?MAIL_IF_NAMES).

get_addr(IfNames) ->
    {ok, IfAddrs} = inet:getifaddrs(),
    get_addr(IfNames, IfAddrs).

get_addr([], _IfAddrs) ->
    {0, 0, 0, 0};
get_addr([IfName|Rest], IfAddrs) ->
    case lists:keysearch(IfName, 1, IfAddrs) of
        {value, {_, IfOpts}} ->
            case lists:keysearch(addr, 1, IfOpts) of
                {value, {_, Addr}} ->
                    Addr;
                false ->
                    get_addr(Rest, IfAddrs)
            end;
        false ->
            get_addr(Rest, IfAddrs)
    end.

%% Exported: get_http_ip_address

get_http_ip_address() ->
    get_addr(?HTTP_IF_NAMES).
