-module(player_bootstrap_service).
-export([start_link/1]).
-export([handle_http_request/4]).

-include_lib("apptools/include/log.hrl").
-include_lib("rester/include/rester.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("rester/include/rester_http.hrl").
-include_lib("rester/include/rester_socket.hrl").
-include_lib("elgamal/include/elgamal.hrl").

-define(BLUETOOTH_INTERFACE, "pan0").
-define(USB_INTERFACE, "usb0").

%%
%% Exported: start_link
%%

start_link(Port) ->
    CertFilename = filename:join([code:priv_dir(player), "cert.pem"]),
    ResterHttpArgs =
	[{request_handler, {?MODULE, handle_http_request, []}},
	 {ifaddr, {0, 0, 0, 0}},
	 {certfile, CertFilename},
	 {verify, verify_none},
	 {nodelay, true},
	 {reuseaddr, true}],
    ?daemon_log_tag_fmt(system, "Bootstrap REST server on 0.0.0.0:~w",
                        [Port]),
    rester_http_server:start(Port, ResterHttpArgs).

%%
%% Exported: handle_http_request
%%

handle_http_request(Socket, Request, Body, Options) ->
    ?dbg_log_fmt("request = ~s, headers=~s, body=~p",
                 [rester_http:format_request(Request),
                  rester_http:format_hdr(Request#http_request.headers),
                  Body]),
    try handle_http_request_(Socket, Request, Body, Options) of
	Result ->
            Result
    catch
	_Class:Reason:StackTrace ->
	    ?error_log_fmt("handle_http_request: crash reason=~p\n~p\n",
                           [Reason, StackTrace]),
	    erlang:error(Reason)
    end.

handle_http_request_(Socket, Request, Body, Options) ->
    case Request#http_request.method of
	'GET' ->
	    handle_http_get(Socket, Request, Body, Options);
	'POST' ->
	    handle_http_post(Socket, Request, Body, Options);
	_ ->
	    rest_util:response(Socket, Request, {error, not_allowed})
    end.

handle_http_get(Socket, Request, Body, Options) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path, "/") of
	["v1" | Tokens] ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, Body, v1);
	["dj" | Tokens] ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, Body, dj);
	Tokens ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

handle_http_get(Socket, Request, _Options, Url, Tokens, _Body, v1) ->
    _Access = rest_util:access(Socket),
    _Accept = rester_http:accept_media(Request),
    UriPath =
        case Tokens of
            [] ->
                "/install.html";
            ["index.html"] ->
                "/install.html";
            _ ->
                Url#url.path
        end,
    AbsFilename =
        filename:join(
          [filename:absname(code:priv_dir(mixmesh)), "docroot",
           tl(UriPath)]),
    case filelib:is_regular(AbsFilename) of
        true ->
            rester_http_server:response_r(
              Socket, Request, 200, "OK", {file, AbsFilename},
              [{content_type, {url, UriPath}}]);
        false ->
            ?dbg_log_fmt("~p not found", [Tokens]),
            rest_util:response(Socket, Request, {error, not_found})
    end;
handle_http_get(Socket, Request, Options, Url, Tokens, _Body, dj) ->
    _Access = rest_util:access(Socket),
    _Accept = rester_http:accept_media(Request),
    case Tokens of
        _ ->
	    handle_http_get(Socket, Request, Url, Options, Tokens, _Body, v1)
    end.

handle_http_post(Socket, Request, Body, Options) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path, "/") of
	["dj" | Tokens] ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, dj);
	Tokens ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

handle_http_post(Socket, Request, _Options, _Url, Tokens, Body, v1) ->
    _Access = rest_util:access(Socket),
    case Tokens of
        ["bootstrap", "install"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       bootstrap_install_post(JsonTerm))
            end;
        ["bootstrap", "reinstall"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       bootstrap_reinstall_post(JsonTerm))
            end;
        ["bootstrap", "restart"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       bootstrap_restart_post(JsonTerm))
            end;
        ["bootstrap", "key", "import"] ->
            case Body of
                {multipart_form_data, FormData} ->
                    rest_util:response(Socket, Request,
                                       bootstrap_key_import_post(FormData));
                _ ->
                    rest_util:response(Socket, Request,
                                       {error, bad_request, "Invalid payload"})
            end;
	_ ->
	    ?dbg_log_fmt("~p not found", [Tokens]),
	    rest_util:response(Socket, Request, {error, not_found})
    end;
handle_http_post(Socket, Request, _Options, _Url, Tokens, _Body, dj) ->
    case Tokens of
	_ ->
	    ?dbg_log_fmt("~p not found", [Tokens]),
	    rest_util:response(Socket, Request, {error, not_found})
    end.

%% /bootstrap/install (POST)

bootstrap_install_post(JsonTerm) ->
    try
        [Nym, RoutingType, UseGps, Longitude, Latitude, SmtpPassword,
         Pop3Password, HttpPassword, SmtpPort, Pop3Port, HttpPort, MixmeshDir,
         Pin] =
            rest_util:parse_json_params(
              JsonTerm,
              [{<<"nym">>, fun erlang:is_binary/1},
               {<<"routing-type">>, fun(<<"blind">>) -> true;
                                       (<<"location">>) -> true;
                                       (_) -> false
                                    end, <<"location">>},
               {<<"use-gps">>, fun erlang:is_boolean/1, true},
               {<<"longitude">>, fun erlang:is_number/1, 0.0},
               {<<"latitude">>, fun erlang:is_number/1, 0.0},
               {<<"smtp-password">>, fun erlang:is_binary/1},
               {<<"pop3-password">>, fun erlang:is_binary/1},
               {<<"http-password">>, fun erlang:is_binary/1},
               {<<"smtp-port">>, fun erlang:is_integer/1, 465},
               {<<"pop3-port">>, fun erlang:is_integer/1, 995},
               {<<"http-port">>, fun erlang:is_integer/1, 443},
               {<<"mixmesh-dir">>, fun erlang:is_binary/1,
                <<"/tmp/mixmesh">>},
               {<<"pin">>, fun erlang:is_binary/1, <<"123456">>}]),
        PinSalt = player_crypto:pin_salt(),
        case player_crypto:make_key_pair(?b2l(Pin), PinSalt, ?b2l(Nym)) of
            {ok, PublicKey, SecretKey, EncryptedSecretKey} ->
                PinFilename = filename:join([MixmeshDir, <<"pin">>]),
                case file:write_file(PinFilename, Pin) of
                    ok ->
                        ok;
                    {error, _Reason} ->
                        throw({error,
                               io_lib:format(
                                 "~s: Could not be created",
                                 [PinFilename])})
                end,
                SourceConfigFilename =
                    filename:join(
                      [code:priv_dir(player), <<"mixmesh.conf.src">>]),
                {ok, SourceConfig} = file:read_file(SourceConfigFilename),
                {MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
                SecondsSinceEpoch = MegaSecs * 1000000 + Secs,
                EncodedPublicKey = base64:encode(PublicKey),
                EncodedSecretKey = base64:encode(SecretKey),
                EncodedEncryptedSecretKey = base64:encode(EncryptedSecretKey),
                EncodedPinSalt = base64:encode(PinSalt),
                TargetConfig =
                    update_config(
                      SourceConfig,
                      [{<<"@@INITIALIZATION-TIME@@">>,
                        ?i2b(trunc(SecondsSinceEpoch))},
                       {<<"@@PUBLIC-KEY@@">>, EncodedPublicKey},
                       {<<"@@SECRET-KEY@@">>, EncodedEncryptedSecretKey},
                       {<<"@@NYM@@">>, Nym},
                       {<<"@@ROUTING-TYPE@@">>, RoutingType},
                       {<<"@@USE-GPS@@">>, ?a2b(UseGps)},
                       {<<"@@LONGITUDE@@">>,
                        float_to_binary(Longitude * 1.0,
                                        [{decimals, 4}, compact])},
                       {<<"@@LATITUDE@@">>,
                        float_to_binary(Latitude * 1.0,
                                        [{decimals, 4}, compact])},
                       {<<"@@SMTP-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(SmtpPassword))},
                       {<<"@@POP3-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(Pop3Password))},
                       {<<"@@HTTP-PASSWORD@@">>, HttpPassword},
                       {<<"@@SMTP-PORT@@">>, ?i2b(SmtpPort)},
                       {<<"@@POP3-PORT@@">>, ?i2b(Pop3Port)},
                       {<<"@@HTTP-PORT@@">>, ?i2b(HttpPort)},
                       {<<"@@MIXMESH-DIR@@">>, MixmeshDir},
                       {<<"@@PIN-SALT@@">>, EncodedPinSalt}]),
                TargetConfigFilename =
                    filename:join([MixmeshDir, <<"mixmesh.conf">>]),
                case file:write_file(TargetConfigFilename, TargetConfig) of
                    ok ->
                        CertFilename =
                            filename:join([code:priv_dir(player),
                                           <<"cert.pem">>]),
                        true = mkconfig:start(MixmeshDir, CertFilename, Nym),
                        MailIpAddress = get_ip_address(?BLUETOOTH_INTERFACE),
                        SmtpAddress =
                            ?l2b(io_lib:format(
                                   "~s:~w",
                                   [inet_parse:ntoa(MailIpAddress), SmtpPort])),
                        Pop3Address =
                            ?l2b(io_lib:format(
                                   "~s:~w",
                                   [inet_parse:ntoa(MailIpAddress), Pop3Port])),
                        HttpIpAddress = get_ip_address(?USB_INTERFACE),
                        %% FIXME
                        %%HttpIpAddress = get_ip_address(?BLUETOOTH_INTERFACE),
                        HttpAddress =
                            ?l2b(io_lib:format(
                                   "~s:~w",
                                   [inet_parse:ntoa(HttpIpAddress), HttpPort])),
                        {ok, {format, [{<<"public-key">>, EncodedPublicKey},
                                       {<<"secret-key">>, EncodedSecretKey},
                                       {<<"routing-type">>, RoutingType},
                                       {<<"use-gps">>, UseGps},
                                       {<<"longitude">>, Longitude},
                                       {<<"latitude">>, Latitude},
                                       {<<"smtp-address">>, SmtpAddress},
                                       {<<"pop3-address">>, Pop3Address},
                                       {<<"http-address">>, HttpAddress},
                                       {<<"mixmesh-dir">>, MixmeshDir},
                                       {<<"pin">>, Pin},
                                       {<<"pin-salt">>, EncodedPinSalt}]}};
                    {error, _Reason2} ->
                        throw({error,
                               io_lib:format(
                                 "~s: Could not be created",
                                 [TargetConfigFilename])})
                end;
            {error, Reason} ->
                throw({error, Reason})
        end
    catch
        throw:{error, ThrowReason} ->
            {error, bad_request, ThrowReason}
    end.

update_config(Config, []) ->
    Config;
update_config(Config, [{Pattern, Replacement}|Rest]) ->
    update_config(binary:replace(Config, Pattern, Replacement, [global]), Rest).

%% /bootstrap/reinstall (POST)

bootstrap_reinstall_post(JsonTerm) ->
    try
        [RoutingType, UseGps, Longitude, Latitude, EncodedPublicKey,
         EncodedSecretKey, SmtpPassword, Pop3Password, HttpPassword, SmtpPort,
         Pop3Port, HttpPort, MixmeshDir, Pin] =
            rest_util:parse_json_params(
              JsonTerm,
              [{<<"routing-type">>, fun(<<"blind">>) -> true;
                                       (<<"location">>) -> true;
                                       (_) -> false
                                    end, <<"location">>},
               {<<"use-gps">>, fun erlang:is_boolean/1, true},
               {<<"longitude">>, fun erlang:is_number/1, 0.0},
               {<<"latitude">>, fun erlang:is_number/1, 0.0},
               {<<"public-key">>, fun erlang:is_binary/1},
               {<<"secret-key">>, fun erlang:is_binary/1},
               {<<"smtp-password">>, fun erlang:is_binary/1},
               {<<"pop3-password">>, fun erlang:is_binary/1},
               {<<"http-password">>, fun erlang:is_binary/1},
               {<<"smtp-port">>, fun erlang:is_integer/1, 465},
               {<<"pop3-port">>, fun erlang:is_integer/1, 995},
               {<<"http-port">>, fun erlang:is_integer/1, 443},
               {<<"mixmesh-dir">>, fun erlang:is_binary/1,
                <<"/tmp/mixmesh">>},
               {<<"pin">>, fun erlang:is_binary/1, <<"123456">>}]),
        UnpackedKeys =
            try
                PublicKeyBin = base64:decode(EncodedPublicKey),
                Pk = elgamal:binary_to_pk(PublicKeyBin),
                {Pk#pk.nym, base64:decode(EncodedSecretKey)}
            catch
                _:_ ->
                    bad_keys
            end,
        case UnpackedKeys of
            bad_keys ->
                throw({error, "Invalid keys"});
            {Nym, DecodedSecretKey} ->
                PinFilename = filename:join([MixmeshDir, <<"pin">>]),
                case file:write_file(PinFilename, Pin) of
                    ok ->
                        ok;
                    {error, _Reason} ->
                        throw({error,
                               io_lib:format(
                                 "~s: Could not be created",
                                 [PinFilename])})
                end,
                {MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
                SecondsSinceEpoch = MegaSecs * 1000000 + Secs,
                PinSalt = player_crypto:pin_salt(),
                SharedKey = player_crypto:generate_shared_key(Pin, PinSalt),
                {ok, EncryptedSecretKey} =
                    player_crypto:shared_encrypt(SharedKey, DecodedSecretKey),
                SourceConfigFilename =
                    filename:join(
                      [code:priv_dir(player), <<"mixmesh.conf.src">>]),
                {ok, SourceConfig} = file:read_file(SourceConfigFilename),
                EncodedEncryptedSecretKey = base64:encode(EncryptedSecretKey),
                EncodedPinSalt = base64:encode(PinSalt),
                TargetConfig =
                    update_config(
                      SourceConfig,
                      [{<<"@@INITIALIZATION-TIME@@">>,
                        ?i2b(trunc(SecondsSinceEpoch))},
                       {<<"@@PUBLIC-KEY@@">>, EncodedPublicKey},
                       {<<"@@SECRET-KEY@@">>, EncodedEncryptedSecretKey},
                       {<<"@@NYM@@">>, Nym},
                       {<<"@@ROUTING-TYPE@@">>, RoutingType},
                       {<<"@@USE-GPS@@">>, ?a2b(UseGps)},
                       {<<"@@LONGITUDE@@">>,
                        float_to_binary(Longitude * 1.0,
                                        [{decimals, 4}, compact])},
                       {<<"@@LATITUDE@@">>,
                        float_to_binary(Latitude * 1.0,
                                        [{decimals, 4}, compact])},
                       {<<"@@SMTP-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(SmtpPassword))},
                       {<<"@@POP3-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(Pop3Password))},
                       {<<"@@HTTP-PASSWORD@@">>, HttpPassword},
                       {<<"@@SMTP-PORT@@">>, ?i2b(SmtpPort)},
                       {<<"@@POP3-PORT@@">>, ?i2b(Pop3Port)},
                       {<<"@@HTTP-PORT@@">>, ?i2b(HttpPort)},
                       {<<"@@MIXMESH-DIR@@">>, MixmeshDir},
                       {<<"@@PIN-SALT@@">>, EncodedPinSalt}]),
                TargetConfigFilename =
                    filename:join([MixmeshDir, <<"mixmesh.conf">>]),
                case file:write_file(TargetConfigFilename, TargetConfig) of
                    ok ->
                        CertFilename =
                            filename:join([code:priv_dir(player),
                                           <<"cert.pem">>]),
                        true = mkconfig:start(MixmeshDir, CertFilename, Nym),
                        MailIpAddress = get_ip_address(?BLUETOOTH_INTERFACE),
                        SmtpAddress =
                            ?l2b(io_lib:format(
                                   "~s:~w",
                                   [inet_parse:ntoa(MailIpAddress), SmtpPort])),
                        Pop3Address =
                            ?l2b(io_lib:format(
                                   "~s:~w",
                                   [inet_parse:ntoa(MailIpAddress), Pop3Port])),
                        HttpIpAddress = get_ip_address(?USB_INTERFACE),
                        %% FIXME
                        %%HttpIpAddress =  get_ip_address(?BLUETOOTH_INTERFACE),
                        HttpAddress =
                            ?l2b(io_lib:format(
                                   "~s:~w",
                                   [inet_parse:ntoa(HttpIpAddress), HttpPort])),
                        {ok, {format, [{<<"nym">>, Nym},
                                       {<<"routing-type">>, RoutingType},
                                       {<<"use-gps">>, UseGps},
                                       {<<"longitude">>, Longitude},
                                       {<<"latitude">>, Latitude},
                                       {<<"smtp-address">>, SmtpAddress},
                                       {<<"pop3-address">>, Pop3Address},
                                       {<<"http-address">>, HttpAddress},
                                       {<<"mixmesh-dir">>, MixmeshDir},
                                       {<<"pin">>, Pin},
                                       {<<"pin-salt">>, EncodedPinSalt}]}};
                    {error, _Reason2} ->
                        throw({error,
                               io_lib:format(
                                 "~s: Could not be created",
                                 [TargetConfigFilename])})
                end
        end
    catch
        throw:{error, ThrowReason} ->
            {error, bad_request, ThrowReason}
    end.

get_ip_address(IfName) ->
    {ok, IfAddrs} = inet:getifaddrs(),
    get_ip_address(IfName, IfAddrs).

get_ip_address(_IfName, []) ->
    {0, 0, 0, 0};
get_ip_address(IfName, [{IfName, IfOpts}|_]) ->
    case lists:keysearch(addr, 1, IfOpts) of
        {value, {_, Addr}} ->
            Addr;
        false ->
            {0, 0, 0, 0}
    end;
get_ip_address(IfName, [_|Rest]) ->
    get_ip_address(IfName, Rest).

%% /bootstrap/restart (POST)

bootstrap_restart_post(Time) when is_integer(Time) andalso Time > 0 ->
    timer:apply_after(Time * 1000, erlang, halt, [0]),
    {ok, "Yes, sir!"};
bootstrap_restart_post(_Time) ->
    {error, bad_request, "Invalid time"}.

%% /bootstrap/key/import (POST)

bootstrap_key_import_post(FormData) ->
    try
        [Nym, MixmeshDir, Pin, EncodedPinSalt] =
            get_form_data(
              FormData,
              [<<"nym">>, <<"mixmesh-dir">>, <<"pin">>, <<"pin-salt">>]),
        PinSalt =
            try
                base64:decode(EncodedPinSalt)
            catch
                _:_ ->
                    bad_format
            end,
        case PinSalt of
            bad_format ->
                {error, bad_request, "Invalid pin-salt"};
            _ ->
                case lists:keysearch(file, 1, FormData) of
                    {value, {_, _Headers, Filename}} ->
                        case local_keydir_serv:new_db(
                               Nym, MixmeshDir, Pin, PinSalt) of
                            {ok, File, SharedKey} ->
                                Result =
                                    player_normal_service:key_import_post(
                                      undefined, Filename,
                                      fun(Pk) ->
                                              local_keydir_serv:write_to_db(
                                                File, SharedKey, Pk)
                                      end),
                                ok = file:close(File),
                                Result;
                            {error, {file, Reason, DbFilename}} ->
                                ReasonString =
                                    io_lib:format(
                                      "~s: ~s",
                                      [DbFilename, file:format_error(Reason)]),
                                {error, bad_request, ReasonString}
                        end;
                    false ->
                        {error, bad_request, "Missing key-file"}
                end
        end
    catch
        throw:{error, ThrowReason} ->
            {error, bad_request, ThrowReason}
    end.

get_form_data(FormData, Names) ->
    sort_form_data(get_form_data_values(FormData, Names), Names).

sort_form_data(_NameValues, []) ->
    [];
sort_form_data(NameValues, [Name|Rest]) ->
    {value, {_, Value}, RemainingNameValues} =
        lists:keytake(Name, 1, NameValues),
    [Value|sort_form_data(RemainingNameValues, Rest)].

get_form_data_values(_FormData, []) ->
    [];
get_form_data_values([], [Name|_]) ->
    throw({error, lists:flatten(io_lib:format("Missing ~s", [Name]))});
get_form_data_values([{data, Headers, Value}|Rest], Names) ->
    case lists:keysearch(<<"Content-Disposition">>, 1, Headers) of
        {value, {_, <<"form-data; name=", FormName/binary>>}} ->
            StrippedFormName = string:trim(FormName, both, "\""),
            case lists:member(StrippedFormName, Names) of
                true ->
                    StrippedValue = string:trim(Value, trailing),
                    [{StrippedFormName, StrippedValue}|
                     get_form_data_values(
                       Rest, lists:delete(StrippedFormName, Names))];
                false ->
                    get_form_data_values(Rest, Names)
            end;
        false ->
            get_form_data_values(Rest, Names)
    end;
get_form_data_values([{file, _Headers, _Filename}|Rest], Names) ->
    get_form_data_values(Rest, Names).
