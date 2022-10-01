-module(player_normal_service).
-export([start_link/5]).
-export([key_import_post/3]).
-export([handle_http_request/4]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("rester/include/rester.hrl").
-include_lib("rester/include/rester_http.hrl").
-include_lib("apptools/include/config_schema.hrl").
-include_lib("elgamal/include/elgamal.hrl").

-define(IDLE_TIMEOUT, infinity). %% 60 * 1000).
-define(SEND_TIMEOUT, infinity). %% default send timeout
-define(ONE_HOUR, 3600).

%%
%% Exported: start_link
%%

start_link(Nym, HttpPassword, TempDir, HttpCertFilename, {IfAddr, Port}) ->
    ResterHttpArgs =
	[{request_handler,
	  {?MODULE, handle_http_request, [{temp_dir, TempDir}]}},
	 {access, [{digest, "", Nym, HttpPassword, "mixmesh"}]},
	 {verify, verify_none},
	 {ifaddr, IfAddr},
	 {certfile, HttpCertFilename},
	 {nodelay, true},
	 {reuseaddr, true}],
    ?daemon_log_tag_fmt(system, "Normal REST server for ~s on ~s:~w",
                        [Nym, inet:ntoa(IfAddr), Port]),
    rester_http_server:start_link(Port, ResterHttpArgs).

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
	    ?daemon_log_fmt("handle_http_request: crash reason=~p\n~p\n",
                            [Reason, StackTrace]),
	    erlang:error(Reason)
    end.

handle_http_request_(Socket, Request, Body, Options) ->
    case Request#http_request.method of
	'GET' ->
	    handle_http_get(Socket, Request, Body, Options);
	'PUT' ->
	    handle_http_put(Socket, Request, Body, Options);
	'POST' ->
	    handle_http_post(Socket, Request, Body, Options);
	_ ->
	    rest_util:response(Socket, Request, {error, not_allowed})
    end.

%% Handle GET request
%% - [vi]/index.htm[l]
%% - /versions                        return an json array of supported versions

handle_http_get(Socket, Request, Body, Options) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path, "/") of
	["versions"] ->
	    Object = jsone:encode([v1, dj, dt]),
	    rester_http_server:response_r(Socket,Request, 200, "OK",
					  Object,
					  [{content_type,"application/json"}]);
	["v1" | Tokens] ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, Body, v1);
	["dj" | Tokens] ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, Body, dj);
	["dt" | Tokens] ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, Body, dt);
	Tokens ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

handle_http_get(Socket, Request, Options, Url, Tokens, _Body, v1) ->
    _Access = rest_util:access(Socket),
    _Accept = rester_http:accept_media(Request),
    case Tokens of
        ["seconds-since-initialization"] ->
            {MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
            SecondsSinceEpoch = MegaSecs * 1000000 + Secs,
            InitializationTime = config:lookup([system, 'initialization-time']),
            rest_util:response(
              Socket, Request,
              {ok, {format, SecondsSinceEpoch - InitializationTime}});
        ["player"] ->
            Nym = config:lookup([player, nym]),
            [PublicKey, SecretKey] =
                config:lookup_children(['public-key', 'secret-key'],
                                       config:lookup([player, routing])),
            {ok, DecryptedSecretKey} = shared_decrypt_secret_key(SecretKey),
            {MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
            SecondsSinceEpoch = MegaSecs * 1000000 + Secs,
            InitializationTime = config:lookup([system, 'initialization-time']),
            JsonTerm =
                [{<<"nym">>, Nym},
                 {<<"public-key">>, base64:encode(PublicKey)}] ++
                if
                    SecondsSinceEpoch - InitializationTime < ?ONE_HOUR ->
                        [{<<"secret-key">>, base64:encode(DecryptedSecretKey)}];
                    true ->
                        []
                end,
            rest_util:response(Socket, Request, {ok, {format, JsonTerm}});
        ["key"] ->
            [KeydirServPid] = get_worker_pids([keydir_serv], Options),
            {ok, PkList} = local_keydir_serv:list(KeydirServPid, all, 100),
            JsonTerm =
                lists:map(
                  fun(Pk) ->
                          [{<<"nym">>, Pk#pk.nym},
                           {<<"public-key">>,
                            base64:encode(
                              elgamal:pk_to_binary(Pk))}]
                  end, PkList),
            rest_util:response(Socket, Request, {ok, {format, JsonTerm}});
        ["key", Nym] ->
            [KeydirServPid] = get_worker_pids([keydir_serv], Options),
            NymBin = ?l2b(Nym),
            case local_keydir_serv:read(KeydirServPid, NymBin) of
                {ok, Pk} ->
                    JsonTerm =
                        [{<<"nym">>, Pk#pk.nym},
                         {<<"public-key">>,
                          base64:encode(elgamal:pk_to_binary(Pk))}],
                    rest_util:response(Socket, Request,
                                       {ok, {format, JsonTerm}});
                {error, no_such_key} ->
                    rest_util:response(Socket, Request, {error, not_found})
            end;
	["temp", TempFilename] ->
            {value, {_, TempDir}} = lists:keysearch(temp_dir, 1, Options),
            AbsFilename = filename:join([TempDir, TempFilename]),
            case filelib:is_regular(AbsFilename) of
                true ->
                    rester_http_server:response_r(
                      Socket, Request, 200, "OK", {file, AbsFilename},
                      [{content_type, {url, Url#url.path}}]);
                false ->
                    ?dbg_log_fmt("~p not found", [Tokens]),
                    rest_util:response(Socket, Request, {error, not_found})
            end;
	Tokens ->
            UriPath =
                case Tokens of
                    [] ->
                        "/me.html";
                    ["index.html"] ->
                        "/me.html";
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
            end
    end;
%% developer T GET code
handle_http_get(Socket, Request, Options, Url, Tokens, _Body, dt) ->
    _Access = rest_util:access(Socket),
    _Accept = rester_http:accept_media(Request),
    case Tokens of
	_ ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, _Body, v1)
    end;
%% developer J GET code
handle_http_get(Socket, Request, Options, Url, Tokens, _Body, dj) ->
    _Access = rest_util:access(Socket),
    _Accept = rester_http:accept_media(Request),
    case Tokens of
        _ ->
	    handle_http_get(Socket, Request, Options, Url, Tokens, _Body, v1)
    end.

get_worker_pids(Ids, Options) ->
    {value, {_, NeighbourWorkers}} =
        lists:keysearch(neighbour_workers, 1, Options),
    supervisor_helper:get_selected_worker_pids(Ids, NeighbourWorkers).

%% General PUT request uri:
%% - [/vi]/item
%%
handle_http_put(Socket, Request, Body, Options) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path,"/") of
	["v1" | Tokens] ->
	    handle_http_put(Socket, Request, Options, Url, Tokens, Body, v1);
	["dt" | Tokens] ->
	    handle_http_put(Socket, Request, Options, Url, Tokens, Body, dt);
	["dj" | Tokens] ->
	    handle_http_put(Socket, Request, Options, Url, Tokens, Body, dj);
	Tokens ->
	    handle_http_put(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

handle_http_put(Socket, Request, Options, _Url, Tokens, Body, v1) ->
    case Tokens of
        ["key"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _} ->
                    rest_util:response(Socket, Request,
                                       {error, bad_request, "Invalid JSON"});
                JsonTerm ->
                    [KeydirServPid] = get_worker_pids([keydir_serv], Options),
                    rest_util:response(Socket, Request,
                                       key_put(KeydirServPid, JsonTerm))
            end;
	_ ->
	    ?dbg_log_fmt("~p not found", [Tokens]),
	    rest_util:response(Socket, Request, {error, not_found})
    end;
%% developer T PUT code
handle_http_put(Socket, Request, Options, Url, Tokens, Body, dt) ->
    case Tokens of
	_Other ->
	    handle_http_put(Socket, Request, Options, Url, Tokens, Body, v1)
    end;
%% developer J PUT code
handle_http_put(Socket, Request, Options, Url, Tokens, Body, dj) ->
    case Tokens of
	_Other ->
	    handle_http_put(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

%% /key (PUT)

key_put(KeydirServPid, PublicKeyBin) when is_binary(PublicKeyBin) ->
    Pk =
        try
            elgamal:binary_to_pk(base64:decode(PublicKeyBin))
        catch
            _:_ ->
                bad_format
        end,
    case Pk of
        bad_format ->
            {error, bad_request, "Invalid public key"};
        _ ->
            case local_keydir_serv:update(KeydirServPid, Pk) of
                ok ->
                    {ok, {format, Pk#pk.nym}};
                {error, no_such_key} ->
                    ok = local_keydir_serv:create(KeydirServPid, Pk),
                    {ok, {format, Pk#pk.nym}}
            end
    end;
key_put(_KeydirServPid, _JsonTerm) ->
    {error, bad_request, "Key is invalid"}.

%% General POST request uri:
%% - [/vi]/item
%%
handle_http_post(Socket, Request, Body, Options) ->
   Url = Request#http_request.uri,
    case string:tokens(Url#url.path,"/") of
	["v1" | Tokens] ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, v1);
	["dt" | Tokens] ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, dt);
	["dj" | Tokens] ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, dj);
	Tokens ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

handle_http_post(Socket, Request, Options, _Url, Tokens, Body, v1) ->
    _Access = rest_util:access(Socket),
    case Tokens of
        ["get-config"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(
                      Socket, Request, get_config_post(JsonTerm))
            end;
        ["edit-config"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(
                      Socket, Request, edit_config_post(JsonTerm))
            end;
        ["key", "filter"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    [KeydirServPid] = get_worker_pids([keydir_serv], Options),
                    rest_util:response(
                      Socket, Request,
                      key_filter_post(KeydirServPid, JsonTerm))
            end;
        ["key", "delete"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    [KeydirServPid] = get_worker_pids([keydir_serv], Options),
                    rest_util:response(Socket, Request,
                                       key_delete_post(KeydirServPid, JsonTerm))
            end;
        ["key", "export"] ->
            case rest_util:parse_body(
                   Request, Body,
                   [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(
                      Socket, Request,
                      {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    [KeydirServPid] = get_worker_pids([keydir_serv], Options),
                    rest_util:response(
                      Socket, Request,
                      key_export_post(Options, KeydirServPid, JsonTerm))
            end;
        ["key", "import"] ->
            case Body of
                {multipart_form_data, FormData} ->
                    [KeydirServPid] = get_worker_pids([keydir_serv], Options),
                    rest_util:response(
                      Socket, Request,
                      key_import_post(KeydirServPid, FormData));
                _ ->
                    rest_util:response(Socket, Request,
                                       {error, bad_request, "Invalid payload"})
            end;
	_ ->
	    ?dbg_log_fmt("~p not found", [Tokens]),
	    rest_util:response(Socket, Request, {error, not_found})
    end;
handle_http_post(Socket, Request, Options, Url, Tokens, Body, dt) ->
    case Tokens of
	_Other ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, v1)
    end;
handle_http_post(Socket, Request, Options, Url, Tokens, Body, dj) ->
    case Tokens of
	_Other ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

%% /get-config (POST)

get_config_post(Filter)
  when is_list(Filter) ->
    try
        AppSchemas = mixmesh_config_serv:get_schemas(),
        {ok, {format, get_config(Filter, AppSchemas)}}
    catch
        throw:{invalid_filter, JsonPath} ->
            {error, bad_request,
             io_lib:format("Invalid filter path ~s",
                           [config_serv:json_path_to_string(JsonPath)])}
    end;
get_config_post(_Filter) ->
    {error, bad_request, "Invalid filter"}.

get_config(Filter, AppSchemas) ->
    get_config(Filter, AppSchemas, []).

get_config([], _AppShchemas, _JsonPath) ->
    [];
get_config([{Name, NestedFilter}|Rest], AppSchemas, JsonPath)
  when is_list(NestedFilter) ->
    [{Name, get_config(NestedFilter, AppSchemas, [?b2a(Name)|JsonPath])}|
     get_config(Rest, AppSchemas, JsonPath)];
get_config([{Name, true}|Rest], AppSchemas, JsonPath) ->
    NewJsonPath = [?b2a(Name)|JsonPath],
    RealJsonPath = lists:reverse(NewJsonPath),
    case config:lookup(RealJsonPath) of
        not_found ->
            throw({invalid_filter, NewJsonPath});
        Values when is_list(Values) ->
            case get_config_type(AppSchemas, RealJsonPath) of
                [#json_type{name = interface_port}] ->
                    %% Do not export the interface name, i.e. keep the
                    %% ip-address.
                    JsonType = #json_type{name = ip_address_port},
                    [{Name, config_serv:unconvert_values(JsonType, Values)}|
                     get_config(Rest, AppSchemas, JsonPath)];
                [JsonType] ->
                    [{Name, config_serv:unconvert_values(JsonType, Values)}|
                     get_config(Rest, AppSchemas, JsonPath)]
            end;
        Value ->
            case get_config_type(AppSchemas, RealJsonPath) of
                #json_type{name = base64} = JsonType ->
                    case RealJsonPath of
                        [player, routing, 'secret-key'] ->
                            %% Decrypt the secret key
                            {ok, DecryptedSecretKey} =
                                shared_decrypt_secret_key(Value),
                            [{Name, config_serv:unconvert_value(
                                      JsonType, DecryptedSecretKey)}|
                             get_config(Rest, AppSchemas, JsonPath)];
                        _ ->
                            [{Name,
                              config_serv:unconvert_value(JsonType, Value)}|
                             get_config(Rest, AppSchemas, JsonPath)]
                    end;
                #json_type{name = interface_port} ->
                    %% Do not export the interface name, i.e. keep the
                    %% ip-address.
                    JsonType = #json_type{name = ip_address_port},
                    [{Name, config_serv:unconvert_value(JsonType, Value)}|
                     get_config(Rest, AppSchemas, JsonPath)];
                JsonType ->
                    [{Name, config_serv:unconvert_value(JsonType, Value)}|
                     get_config(Rest, AppSchemas, JsonPath)]
            end
    end;
get_config([{Name, _NotBoolean}|_Rest], _AppSchemas, JsonPath) ->
    throw({invalid_filter, [?b2a(Name)|JsonPath]});
get_config(_Filter, _AppSchemas, JsonPath) ->
    throw({invalid_filter, JsonPath}).

get_config_type(AppSchemas, [Name|_Rest] = JsonPath) ->
    {value, {_, Schema}} = lists:keysearch(Name, 1, AppSchemas),
    get_schema_type(Schema, JsonPath).

get_schema_type([{Name, JsonType}|_], [Name]) ->
    JsonType;
get_schema_type([{Name, NestedSchema}|_], [Name|JsonPathRest]) ->
    get_schema_type(NestedSchema, JsonPathRest);
get_schema_type([_|SchemaRest], JsonPath) ->
    get_schema_type(SchemaRest, JsonPath).

shared_decrypt_secret_key(DecodedSecretKey) ->
    MixmeshDir = config:lookup([system, 'mixmesh-dir']),
    PinFilename = filename:join([MixmeshDir, <<"pin">>]),
    {ok, Pin} = file:read_file(PinFilename),
    PinSalt = config:lookup([system, 'pin-salt']),
    SharedKey = player_crypto:generate_shared_key(Pin, PinSalt),
    player_crypto:shared_decrypt(SharedKey, DecodedSecretKey).

%% /edit-config (POST)

edit_config_post(JsonTerm) ->
    try
        AppSchemas = mixmesh_config_serv:get_schemas(),
        Result = edit_config(config_serv:atomify(JsonTerm), AppSchemas),
        ok = config_serv:export_config_file(),
        Result
    catch
        throw:Reason ->
            {error, bad_request,
             ?b2l(config_serv:format_error({config, Reason}))}
    end.

edit_config(JsonTerm, AppSchemas) ->
    {App, FirstNameInJsonPath, Schema, RemainingAppSchemas} =
        config_serv:lookup_schema(AppSchemas, JsonTerm),
    case config_serv:convert(<<"/tmp">>, Schema, JsonTerm, true) of
        {NewJsonTerm, []} ->
            {ok, OldJsonTerm} = application:get_env(App, FirstNameInJsonPath),
            MergedJsonTerm = edit_config_merge(OldJsonTerm, NewJsonTerm),
            ok = application:set_env(App, FirstNameInJsonPath, MergedJsonTerm),
            ?dbg_log({new_merged_config, MergedJsonTerm}),
            {ok, "Config has been updated"};
        {NewJsonTerm, RemainingJsonTerm} ->
            {ok, OldJsonTerm} = application:get_env(App, FirstNameInJsonPath),
            MergedJsonTerm = edit_config_merge(OldJsonTerm, NewJsonTerm),
            ok = application:set_env(App, FirstNameInJsonPath, MergedJsonTerm),
            ?dbg_log({new_merged_config, MergedJsonTerm}),
            edit_config(RemainingJsonTerm, RemainingAppSchemas)
    end.

edit_config_merge([], _NewJsonTerm) ->
    [];
edit_config_merge([{Name, OldValue}|OldJsonTerm],
                  [{Name, NewValue}|NewJsonTerm])
  when is_list(OldValue) ->
    [{Name, edit_config_merge(OldValue, NewValue)}|
     edit_config_merge(OldJsonTerm, NewJsonTerm)];
edit_config_merge([{Name, _OldValue}|OldJsonTerm],
                  [{Name, NewValue}|NewJsonTerm]) ->
    [{Name, NewValue}|edit_config_merge(OldJsonTerm, NewJsonTerm)];
edit_config_merge([{Name, OldValue}|OldJsonTerm], NewJsonTerm) ->
    [{Name, OldValue}|edit_config_merge(OldJsonTerm, NewJsonTerm)].

%% /key/filter (POST)

key_filter_post(KeydirServPid, JsonTerm) ->
    key_filter(KeydirServPid, JsonTerm, {[], 100}).

key_filter(_KeydirServPid, SubStringNyms, {PkAcc, N})
  when SubStringNyms == [] orelse N == 0 ->
    JsonTerm =
        lists:map(
          fun(Pk) ->
                  [{<<"nym">>, Pk#pk.nym},
                   {<<"public-key">>, base64:encode(elgamal:pk_to_binary(Pk))}]
          end, lists:usort(
                 fun(Pk1, Pk2) ->
                         Pk1#pk.nym < Pk2#pk.nym
                 end, PkAcc)),
    {ok, {format, JsonTerm}};
key_filter(KeydirServPid, [SubStringNym|Rest], {PkAcc, N})
  when is_binary(SubStringNym) ->
    {ok, Pks} =
        local_keydir_serv:list(KeydirServPid, {substring, SubStringNym}, N),
    key_filter(KeydirServPid, Rest, {Pks ++ PkAcc, N - 1});
key_filter(_KeydirServPid, _SubStringNyms, {_PkAcc, _N}) ->
    {error, bad_request, "Invalid filter"}.

%% /key/delete (POST)

key_delete_post(KeydirServPid, Nyms) when is_list(Nyms) ->
    key_delete(KeydirServPid, Nyms, []);
key_delete_post(_KeydirServPid, _JsonTerm) ->
    {error, bad_request, "Invalid nyms"}.

key_delete(_KeydirServPid, [], Failures) ->
    JsonTerm =
        lists:map(
          fun({Nym, Reason}) ->
                  [{<<"nym">>, Nym},
                   {<<"reason">>, local_keydir_serv:strerror(Reason)}]
          end, Failures),
    {ok, {format, JsonTerm}};
key_delete(KeydirServPid, [Nym|Rest], Failures)
  when is_binary(Nym) ->
    case local_keydir_serv:delete(KeydirServPid, Nym) of
        ok ->
            key_delete(KeydirServPid, Rest, Failures);
        {error, Reason} ->
            key_delete(KeydirServPid, Rest, [{Nym, Reason}|Failures])
    end;
key_delete(KeydirServPid, [_|Rest], Failures) ->
    key_delete(KeydirServPid, Rest, Failures).

%% /key/export (POST)

key_export_post(Options, KeydirServPid, <<"all">>) ->
{ok, Nyms} = local_keydir_serv:all_nyms(KeydirServPid),
    key_export_post(Options, KeydirServPid, Nyms);
key_export_post(Options, KeydirServPid, Nyms) when is_list(Nyms) ->
    TempFilename = "keys-" ++ ?i2l(erlang:unique_integer([positive])) ++ ".bin",
    {value, {_, TempDir}} = lists:keysearch(temp_dir, 1, Options),
    AbsFilename = filename:join([TempDir, TempFilename]),
    UriPath = filename:join(["/temp", TempFilename]),
    {ok, File} = file:open(AbsFilename, [write, binary]),
    key_export(KeydirServPid, Nyms, UriPath, File, 0, erlang:md5_init());
key_export_post(_Options, _KeydirServPid, _Nyms) ->
    {error, bad_request, "Invalid nyms"}.

key_export(_KeydirServPid, [], UriPath, File, N, MD5Context) ->
    Digest = erlang:md5_final(MD5Context),
    DigestSize = size(Digest),
    DigestPacket = <<0:16/unsigned-integer,
                     DigestSize:16/unsigned-integer, Digest/binary>>,
    ok = file:write(File, DigestPacket),
    ok = file:close(File),
    {ok, {format, [{<<"size">>, N}, {<<"uri-path">>, ?l2b(UriPath)}]}};
key_export(KeydirServPid, [Nym|Rest], UriPath, File, N, MD5Context)
  when is_binary(Nym) ->
    case local_keydir_serv:read(KeydirServPid, Nym) of
        {ok, Pk} ->
            PublicKeyBin = elgamal:pk_to_binary(Pk),
            PublicKeyBinSize = size(PublicKeyBin),
            Packet = <<PublicKeyBinSize:16/unsigned-integer, PublicKeyBin/binary>>,
            ok = file:write(File, Packet),
            NewMD5Context = erlang:md5_update(MD5Context, Packet),
            key_export(KeydirServPid, Rest, UriPath, File, N + 1,
                       NewMD5Context);
        {error, no_such_key} ->
            key_export(KeydirServPid, Rest, UriPath, File, N, MD5Context)
    end;
key_export(_KeydirServPid, _Nyms, _UriPath, _File, _N, _MD5Context) ->
    {error, bad_request, "Invalid nyms"}.

%% /key/import (POST)

key_import_post(KeydirServPid, FormData) ->
    case lists:keysearch(file, 1, FormData) of
        {value, {_, _Headers, Filename}} ->
            key_import_post(
              KeydirServPid, Filename,
              fun(Pk) ->
                      case local_keydir_serv:update(KeydirServPid, Pk) of
                          ok ->
                              ok;
                          {error, no_such_key} ->
                              ok = local_keydir_serv:create(KeydirServPid, Pk)
                      end
              end);
        false ->
            {error, bad_request, "Missing key-file"}
    end.

%%
%% Exported: key_import_post
%%

key_import_post(KeydirServPid, Filename, UpdatePublicKey) ->
    {ok, File} = file:open(Filename, [read, binary]),
    key_import(KeydirServPid, UpdatePublicKey, File, 0, erlang:md5_init()).

key_import(KeydirServPid, UpdatePublicKey, File, N, MD5Context) ->
    case file:read(File, 2) of
        {ok, <<0:16/unsigned-integer>>} ->
            case file:read(File, 2) of
                {ok, <<DigestSize:16/unsigned-integer>>} ->
                    case file:read(File, DigestSize) of
                        {ok, Digest} ->
                            case erlang:md5_final(MD5Context) of
                                Digest ->
                                    ok = file:close(File),
                                    {ok, {format, N}};
                                _ ->
                                    ok = file:close(File),
                                    {error, bad_request, "Digest mismatch"}
                            end;
                        _ ->
                            ok = file:close(File),
                            {error, bad_request, "Invalid digest"}
                    end;
                _ ->
                    ok = file:close(File),
                    {error, bad_request, "Invalid digest size"}
            end;
        {ok, <<PublicKeyBinSize:16/unsigned-integer>>} ->
            case file:read(File, PublicKeyBinSize) of
                {ok, PublicKeyBin} ->
                    Pk =
                        try
                            elgamal:binary_to_pk(PublicKeyBin)
                        catch
                            _:_ ->
                                bad_key
                        end,
                    case Pk of
                        bad_key ->
                            ok = file:close(File),
                            {error, bad_request, "Not in Base64 format"};
                        _ ->
                            case UpdatePublicKey(Pk) of
                                ok ->
                                    Packet =
                                        <<PublicKeyBinSize:16/unsigned-integer,
                                          PublicKeyBin/binary>>,
                                    NewMD5Context =
                                        erlang:md5_update(MD5Context, Packet),
                                    key_import(
                                      KeydirServPid, UpdatePublicKey, File,
                                      N + 1, NewMD5Context);
                                {error, permission_denied} ->
                                    {error, no_access}
                            end
                    end;
                _ ->
                    {error, bad_request, "Invalid public key"}
            end;
        eof ->
            ok = file:close(File),
            {error, bad_request, "Bad file format"};
        {error, _Reason} ->
            {error, bad_request, "Invalid public key size"}
    end.
