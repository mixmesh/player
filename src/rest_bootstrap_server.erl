-module(rest_bootstrap_server).
-export([start_link/1]).
-export([handle_http_request/4]).

-include_lib("apptools/include/log.hrl").
-include_lib("rester/include/rester.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("rester/include/rester_http.hrl").
-include_lib("rester/include/rester_socket.hrl").
-include_lib("elgamal/include/elgamal.hrl").

%% Exported: start_link

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

%% Exported: handle_http_request

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
	    ?log_error("handle_http_request: crash reason=~p\n~p\n",
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
          [filename:absname(code:priv_dir(obscrete)), "docroot",
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
        ["system", "install"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       system_install_post(JsonTerm))
            end;
        ["system", "reinstall"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       system_reinstall_post(JsonTerm))
            end;
        ["system", "restart"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       system_restart_post(JsonTerm))
            end;
        ["key", "import"] ->
            case Body of
                {multipart_form_data, FormData} ->
                    rest_util:response(Socket, Request,
                                       key_import_post(FormData));
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

%% /system/install (POST)

system_install_post(JsonTerm) ->
    try
        [Nym, SmtpPassword, Pop3Password, HttpPassword,
         SyncAddress, SmtpAddress, Pop3Address, HttpAddress, ObscreteDir, Pin] =
            rest_util:parse_json_params(
              JsonTerm,
              [{<<"nym">>, fun erlang:is_binary/1},
               {<<"smtp-password">>, fun erlang:is_binary/1},
               {<<"pop3-password">>, fun erlang:is_binary/1},
               {<<"http-password">>, fun erlang:is_binary/1},
               {<<"sync-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:9900">>},
               {<<"smtp-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:19900">>},
               {<<"pop3-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:29900">>},
               {<<"http-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:8444">>},
               {<<"obscrete-dir">>, fun erlang:is_binary/1,
                <<"/tmp/obscrete">>},
               {<<"pin">>, fun erlang:is_binary/1, <<"123456">>}]),
        PinSalt = player_crypto:pin_salt(),
        case player_crypto:make_key_pair(?b2l(Pin), PinSalt, ?b2l(Nym)) of
            {ok, PublicKey, SecretKey, EncryptedSecretKey} ->
                SourceConfigFilename =
                    filename:join(
                      [code:priv_dir(player), <<"obscrete.conf.src">>]),
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
                       {<<"@@SMTP-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(SmtpPassword))},
                       {<<"@@POP3-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(Pop3Password))},
                       {<<"@@HTTP-PASSWORD@@">>, HttpPassword},
                       {<<"@@SYNC-ADDRESS@@">>, SyncAddress},
                       {<<"@@SMTP-ADDRESS@@">>, SmtpAddress},
                       {<<"@@POP3-ADDRESS@@">>, Pop3Address},
                       {<<"@@HTTP-ADDRESS@@">>, HttpAddress},
                       {<<"@@OBSCRETE-DIR@@">>, ObscreteDir},
                       {<<"@@PIN@@">>, Pin},
                       {<<"@@PIN-SALT@@">>, EncodedPinSalt}]),
                TargetConfigFilename =
                    filename:join([ObscreteDir, <<"obscrete.conf">>]),
                case file:write_file(TargetConfigFilename, TargetConfig) of
                    ok ->
                        CertFilename =
                            filename:join([code:priv_dir(player),
                                           <<"cert.pem">>]),
                        true = mkconfig:start(ObscreteDir, CertFilename, Nym),
                        {ok, {format, [{<<"public-key">>, EncodedPublicKey},
                                       {<<"secret-key">>, EncodedSecretKey},
                                       {<<"sync-address">>, SyncAddress},
                                       {<<"smtp-address">>, SmtpAddress},
                                       {<<"pop3-address">>, Pop3Address},
                                       {<<"http-address">>, HttpAddress},
                                       {<<"obscrete-dir">>, ObscreteDir},
                                       {<<"pin">>, Pin},
                                       {<<"pin-salt">>, EncodedPinSalt}]}};
                    {error, _Reason} ->
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

%% /system/reinstall (POST)

system_reinstall_post(JsonTerm) ->
    try
        [EncodedPublicKey, EncodedSecretKey, SmtpPassword, Pop3Password,
         HttpPassword, SyncAddress, SmtpAddress, Pop3Address, HttpAddress,
         ObscreteDir, Pin] =
            rest_util:parse_json_params(
              JsonTerm,
              [{<<"public-key">>, fun erlang:is_binary/1},
               {<<"secret-key">>, fun erlang:is_binary/1},
               {<<"smtp-password">>, fun erlang:is_binary/1},
               {<<"pop3-password">>, fun erlang:is_binary/1},
               {<<"http-password">>, fun erlang:is_binary/1},
               {<<"sync-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:9900">>},
               {<<"smtp-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:19900">>},
               {<<"pop3-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:29900">>},
               {<<"http-address">>, fun erlang:is_binary/1,
                <<"0.0.0.0:8444">>},
               {<<"obscrete-dir">>, fun erlang:is_binary/1,
                <<"/tmp/obscrete">>},
               {<<"pin">>, fun erlang:is_binary/1, <<"123456">>}]),
        UnpackedKeys =
            try
                PublicKeyBin = base64:decode(EncodedPublicKey),
                PublicKey = elgamal:binary_to_public_key(PublicKeyBin),
                {PublicKey#pk.nym, base64:decode(EncodedSecretKey)}
            catch
                _:_ ->
                    bad_keys
            end,
        case UnpackedKeys of
            bad_keys ->
                throw({error, "Invalid keys"});
            {Nym, DecodedSecretKey} ->
                {MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
                SecondsSinceEpoch = MegaSecs * 1000000 + Secs,
                PinSalt = player_crypto:pin_salt(),
                SharedKey = player_crypto:generate_shared_key(Pin, PinSalt),
                {ok, EncryptedSecretKey} =
                    player_crypto:shared_encrypt(SharedKey, DecodedSecretKey),
                SourceConfigFilename =
                    filename:join(
                      [code:priv_dir(player), <<"obscrete.conf.src">>]),
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
                       {<<"@@SMTP-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(SmtpPassword))},
                       {<<"@@POP3-PASSWORD-DIGEST@@">>,
                        base64:encode(
                          player_crypto:digest_password(Pop3Password))},
                       {<<"@@HTTP-PASSWORD@@">>, HttpPassword},
                       {<<"@@SYNC-ADDRESS@@">>, SyncAddress},
                       {<<"@@SMTP-ADDRESS@@">>, SmtpAddress},
                       {<<"@@POP3-ADDRESS@@">>, Pop3Address},
                       {<<"@@HTTP-ADDRESS@@">>, HttpAddress},
                       {<<"@@OBSCRETE-DIR@@">>, ObscreteDir},
                       {<<"@@PIN@@">>, Pin},
                       {<<"@@PIN-SALT@@">>, EncodedPinSalt}]),
                TargetConfigFilename =
                    filename:join([ObscreteDir, <<"obscrete.conf">>]),
                case file:write_file(TargetConfigFilename, TargetConfig) of
                    ok ->
                        CertFilename =
                            filename:join([code:priv_dir(player),
                                           <<"cert.pem">>]),
                        true = mkconfig:start(ObscreteDir, CertFilename, Nym),
                        {ok, {format, [{<<"nym">>, Nym},
                                       {<<"sync-address">>, SyncAddress},
                                       {<<"smtp-address">>, SmtpAddress},
                                       {<<"pop3-address">>, Pop3Address},
                                       {<<"http-address">>, HttpAddress},
                                       {<<"obscrete-dir">>, ObscreteDir},
                                       {<<"pin">>, Pin},
                                       {<<"pin-salt">>, EncodedPinSalt}]}};
                    {error, _Reason} ->
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

%% /system/restart (POST)

system_restart_post(Time) when is_integer(Time) andalso Time > 0 ->
    timer:apply_after(Time * 1000, erlang, halt, [0]),
    {ok, "Yes, sir!"};
system_restart_post(_Time) ->
    {error, bad_request, "Invalid time"}.

%% /key/import (POST)

%% {multipart_form_data,[{data,[{<<"Content-Disposition">>,
%%                                     <<"form-data; name=\"c\"">>}],
%%                                   <<"d\r\n">>},
%%                             {data,[{<<"Content-Disposition">>,
%%                                     <<"form-data; name=\"a\"">>}],
%%                                   <<"b\r\n">>},
%%                             {file,[{<<"Content-Type">>,
%%                                     <<"application/octet-stream">>},
%%                                    {<<"Content-Disposition">>,
%%                                     <<"form-data; name=\"key-file\"; filename=\"keys-6.bin\"">>}],
%%                                   "/tmp/form-data-8"}]}

key_import_post(FormData) ->
    try
        [Nym, ObscreteDir, Pin, EncodedPinSalt] =
            get_form_data(
              FormData,
              [<<"nym">>, <<"obscrete-dir">>, <<"pin">>, <<"pin-salt">>]),
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
                        case local_pki_serv:new_db(
                               Nym, ObscreteDir, Pin, PinSalt) of
                            {ok, File, SharedKey} ->
                                Result =
                                    rest_normal_server:key_import_post(
                                      undefined, Filename,
                                      fun(PublicKey) ->
                                              local_pki_serv:write_to_db(
                                                File, SharedKey, PublicKey)
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
