-module(rest_normal_server).
-export([start_link/5]).
-export([handle_http_request/4]).
-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("rester/include/rester.hrl").
-include_lib("rester/include/rester_http.hrl").
-include_lib("apptools/include/config_schema.hrl").
-include_lib("pki/include/pki_serv.hrl").

-define(IDLE_TIMEOUT, infinity). %% 60 * 1000).
-define(SEND_TIMEOUT, infinity). %% default send timeout

%% Exported: start_link

start_link(Nym, HttpPassword, TempDir, HttpCertFilename, {IfAddr,Port}) ->
    S0 = [],
    IdleTimeout =
	case proplists:get_value(idle_timeout, S0, ?IDLE_TIMEOUT) of
	    I when is_integer(I) -> I + 100; %% Give some extra time
	    T -> T
	end,
    SendTimeout =
	proplists:get_value(send_timeout, S0, ?SEND_TIMEOUT),
    S01 = lists:foldl(fun(Key,Ai) ->
			      proplists:delete(Key,Ai)
		      end, S0, [port,idle_timeout,send_timeout]),
    ResterHttpArgs =
	[{request_handler,
	  {?MODULE, handle_http_request, [{temp_dir, TempDir}]}},
	 %% FIXME: we should probably only allow digest!
	 {access, [%% {basic,"",Nym,HttpPassword,"obscrete"},
		   {digest,"",Nym,HttpPassword,"obscrete"}]},
	 {verify, verify_none},
	 {ifaddr, IfAddr},
	 {certfile, HttpCertFilename},
	 {nodelay, true},
	 {reuseaddr, true},
	 {idle_timeout, IdleTimeout},
	 {send_timeout, SendTimeout}|S01],
    ?daemon_log_tag_fmt(system, "Normal REST server for ~s on ~s:~w",
                        [Nym, inet:ntoa(IfAddr), Port]),
    rester_http_server:start_link(Port, ResterHttpArgs).

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
    case string:tokens(Url#url.path,"/") of
	["versions"] ->
	    Object = jsone:encode([v1,dj,dt]),
	    rester_http_server:response_r(Socket,Request,200, "OK",
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

handle_http_get(Socket, Request, _Options, Url, Tokens, _Body, v1) ->
    _Access = rest_util:access(Socket),
    Accept = rester_http:accept_media(Request),
    case Tokens of
        ["index.html"] ->
            rest_util:response(Socket, Request, rest_util:index(Accept));
        ["index.htm"] ->
            rest_util:response(Socket, Request, rest_util:index(Accept));
        ["index"] ->
            rest_util:response(Socket, Request, rest_util:index(Accept));
        [] ->
            rest_util:response(Socket, Request, rest_util:index(Accept));
        ["system-time"] ->
            rest_util:response(
              Socket, Request,
              {ok, integer_to_list(erlang:system_time(milli_seconds))});
        ["public"] ->
            %% list public keys in a table
            Tab = ets:foldl(
	 	    fun(#pki_user{nym=Name,public_key=Pk}, Acc) ->
	 		    MD5 = crypto:hash(
                                    md5, elgamal:public_key_to_binary(Pk)),
	 		    Fs = [tl(integer_to_list(B+16#100,16)) ||
	 			     <<B>> <= MD5],
	 		    [{Name, Fs}|Acc]
	 	    end, [], pki_db),
            rest_util:response(Socket,Request,
                               rest_util:html_doc(rest_util:html_table(Tab)));
	_ ->
            AbsFilename =
                filename:join(
                  [filename:absname(code:priv_dir(obscrete)), "docroot",
                   tl(Url#url.path)]),
            case filelib:is_regular(AbsFilename) of
                true ->
                    rester_http_server:response_r(
                      Socket, Request, 200, "OK", {file, AbsFilename},
                      [{content_type, {url, Url#url.path}}]);
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
	    handle_http_get(Socket, Request, Url, Options, Tokens, _Body, v1)
    end;
%% developer J GET code
handle_http_get(Socket, Request, Options, Url, Tokens, _Body, dj) ->
    _Access = rest_util:access(Socket),
    _Accept = rester_http:accept_media(Request),
    case Tokens of
        ["player"] ->
            %% FIXME: Mask the secret key one hour after box initialization
            Nym = config:lookup([player, nym]),
            [PublicKey, SecretKey] =
                config:lookup_children(['public-key', 'secret-key'],
                                       config:lookup([player, spiridon])),
            {ok, DecryptedSecretKey} = shared_decrypt_secret_key(SecretKey),
            JsonTerm =
                [{<<"nym">>, Nym},
                 {<<"public-key">>, base64:encode(PublicKey)},
                 {<<"secret-key">>, base64:encode(DecryptedSecretKey)}],
            rest_util:response(Socket, Request, {ok, {format, JsonTerm}});
        ["key"] ->
            [PkiServPid] = get_worker_pids([pki_serv], Options),
            {ok, PublicKeys} = local_pki_serv:list(PkiServPid, all, 100),
            JsonTerm =
                lists:map(
                  fun(PublicKey) ->
                          [{<<"nym">>, PublicKey#pk.nym},
                           {<<"public-key">>, 
                            base64:encode(
                              elgamal:public_key_to_binary(PublicKey))}]
                  end, PublicKeys),
            rest_util:response(Socket, Request, {ok, {format, JsonTerm}});
        ["key", Nym] ->
            [PkiServPid] = get_worker_pids([pki_serv], Options),
            NymBin = ?l2b(Nym),
            case local_pki_serv:read(PkiServPid, NymBin) of
                {ok, PublicKey} ->
                    JsonTerm = base64:encode(
                                 elgamal:public_key_to_binary(PublicKey)),
                    rest_util:response(Socket, Request,
                                       {ok, {format, JsonTerm}});
                {error, no_such_key} ->
                    rest_util:response(Socket, Request, {error, not_found})
            end;
        _ ->
	    handle_http_get(Socket, Request, Url, Options, Tokens, _Body, v1)
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

handle_http_put(Socket, Request, _Options, _Url, Tokens, _Body, v1) ->
    case Tokens of
	Tokens ->
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
        ["key"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON"});
                JsonTerm ->
                    [PkiServPid] = get_worker_pids([pki_serv], Options),
                    rest_util:response(Socket, Request,
                                       key_put(PkiServPid, JsonTerm))
            end;
	_Other ->
	    handle_http_put(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

%% dj/key (PUT)

key_put(PkiServPid, PublicKeyBin) when is_binary(PublicKeyBin) ->
    PublicKey =
        try
            elgamal:binary_to_public_key(base64:decode(PublicKeyBin))
        catch
            _:_ ->
                bad_format
        end,
    case PublicKey of
        bad_format ->
            {error, bad_request, "Invalid public key"};
        _ ->
            case local_pki_serv:update(PkiServPid, PublicKey) of
                ok ->
                    {ok, "Key has been updated"};
                {error, no_such_key} ->
                    ok = local_pki_serv:create(PkiServPid, PublicKey),
                    {ok, "Key has been added"};
                {error, permission_denied} ->
                    {error, no_access}
            end
    end;
key_put(_PkiServPid, _JsonTerm) ->
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

handle_http_post(Socket, Request, _Options, _Url, Tokens, Body, v1) ->
    _Access = rest_util:access(Socket),
    _Data = rest_util:parse_body(Request, Body),
    case Tokens of
	Tokens ->
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
        ["get-config"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       get_config_post(JsonTerm))
            end;
        ["edit-config"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request,
                                       edit_config_post(JsonTerm))
            end;

        ["key", "filter"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    [PkiServPid] = get_worker_pids([pki_serv], Options),
                    rest_util:response(Socket, Request,
                             key_filter_post(PkiServPid, JsonTerm))
            end;
        ["key", "delete"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    [PkiServPid] = get_worker_pids([pki_serv], Options),
                    rest_util:response(Socket, Request,
                             key_delete_post(PkiServPid, JsonTerm))
            end;
        ["key", "export"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    [PkiServPid] = get_worker_pids([pki_serv], Options),
                    rest_util:response(Socket, Request,
                             key_export_post(Options, PkiServPid, JsonTerm))
            end;
        ["key", "import"] ->
            case Body of
                {file, Filename} ->
                    [PkiServPid] = get_worker_pids([pki_serv], Options),
                    rest_util:response(Socket, Request,
                                       key_import_post(PkiServPid, Filename));
                _ ->
                    rest_util:response(Socket, Request,
                                       {error, bad_request, "Invalid payload"})
            end;
	_Other ->
	    handle_http_post(Socket, Request, Options, Url, Tokens, Body, v1)
    end.

%% /dj/get-config (POST)

get_config_post(Filter) ->
    try
        AppSchemas = obscrete_config_serv:get_schemas(),
        {ok, {format, get_config(Filter, AppSchemas)}}
    catch
        throw:{invalid_filter, JsonPath} ->
            {error, bad_request,
             io_lib:format("Invalid filter path ~s",
                           [config_serv:json_path_to_string(JsonPath)])}
    end.

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
        Value when is_list(Value) ->
            throw({invalid_filter, NewJsonPath});
        Value ->
            case get_config_type(AppSchemas, RealJsonPath) of
                base64 ->
                    case RealJsonPath of
                        [player, spiridon, 'secret-key'] ->
                            {ok, DecryptedSecretKey} =
                                shared_decrypt_secret_key(Value),
                            [{Name, base64:encode(DecryptedSecretKey)}|
                             get_config(Rest, AppSchemas, JsonPath)];
                        _ ->
                            [{Name, base64:encode(Value)}|
                             get_config(Rest, AppSchemas, JsonPath)]
                    end;
                _ ->
                    [{Name, Value}|get_config(Rest, AppSchemas, JsonPath)]
            end
    end;
get_config([{Name, _NotBoolean}|_Rest], _AppSchemas, JsonPath) ->
    throw({invalid_filter, [?b2a(Name)|JsonPath]});
get_config(_ConfigFilter, _AppSchemas, JsonPath) ->
    throw({invalid_filter, JsonPath}).

get_config_type(AppSchemas, [Name|_Rest] = JsonPath) ->
    {value, {_, Schema}} = lists:keysearch(Name, 1, AppSchemas),
    get_schema_type(Schema, JsonPath).

get_schema_type([{Name, #json_type{name = TypeName}}|_], [Name]) ->
    TypeName;
get_schema_type([{Name, NestedSchema}|_], [Name|JsonPathRest]) ->
    get_schema_type(NestedSchema, JsonPathRest);
get_schema_type([_|SchemaRest], JsonPath) ->
    get_schema_type(SchemaRest, JsonPath).

shared_decrypt_secret_key(DecodedSecretKey) ->
    Pin = config:lookup([system, pin]),
    PinSalt = config:lookup([system, 'pin-salt']),
    SharedKey = player_crypto:generate_shared_key(Pin, PinSalt),
    player_crypto:shared_decrypt(SharedKey, DecodedSecretKey).

%% /dj/edit-config (POST)

edit_config_post(JsonTerm) ->
    try
        AppSchemas = obscrete_config_serv:get_schemas(),
        edit_config(config_serv:atomify(JsonTerm), AppSchemas)
    catch
        throw:Reason ->
            {error, bad_request,
             ?b2l(config_serv:format_error({config, Reason}))}
    end.

edit_config(JsonTerm, AppSchemas) ->
    {App, FirstNameInJsonPath, Schema, RemainingAppSchemas} =
        config_serv:lookup_schema(AppSchemas, JsonTerm),
    case config_serv:validate(<<"/tmp">>, Schema, JsonTerm, true) of
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

%% /dj/key/filter (POST)

key_filter_post(PkiServPid, JsonTerm) ->
    key_filter(PkiServPid, JsonTerm, {[], 100}).

key_filter(_PkiServPid, SubStringNyms, {PublicKeysAcc, N})
  when SubStringNyms == [] orelse N == 0 ->
    JsonTerm =
        lists:map(
          fun(PublicKey) ->
                  [{<<"nym">>, PublicKey#pk.nym},
                   {<<"public-key">>,
                    base64:encode(elgamal:public_key_to_binary(PublicKey))}]
          end, lists:usort(
                 fun(PublicKey1, PublicKey2) ->
                         PublicKey1#pk.nym < PublicKey2#pk.nym
                 end, PublicKeysAcc)),
    {ok, {format, JsonTerm}};
key_filter(PkiServPid, [SubStringNym|Rest], {PublicKeysAcc, N})
  when is_binary(SubStringNym) ->
    {ok, PublicKeys} =
        local_pki_serv:list(PkiServPid, {substring, SubStringNym}, N),
    key_filter(PkiServPid, Rest, {PublicKeys ++ PublicKeysAcc, N - 1});
key_filter(_PkiServPid, _SubStringNyms, {_PublicKeysAcc, _N}) ->
    {error, bad_request, "Invalid filter"}.

%% /dj/key/delete (POST)

key_delete_post(PkiServPid, Nyms) when is_list(Nyms) ->
    key_delete(PkiServPid, Nyms, []);
key_delete_post(_PkiServPid, _JsonTerm) ->
    {error, bad_request, "Invalid nyms"}.

key_delete(_PkiServPid, [], Failures) ->
    JsonTerm =
        lists:map(
          fun({Nym, Reason}) ->
                  [{<<"nym">>, Nym},
                   {<<"reason">>, local_pki_serv:strerror(Reason)}]
          end, Failures),
    {ok, {format, JsonTerm}};
key_delete(PkiServPid, [Nym|Rest], Failures)
  when is_binary(Nym) ->
    case local_pki_serv:delete(PkiServPid, Nym) of
        ok ->
            key_delete(PkiServPid, Rest, Failures);
        {error, Reason} ->
            key_delete(PkiServPid, Rest, [{Nym, Reason}|Failures])
    end;
key_delete(PkiServPid, [_|Rest], Failures) ->
    key_delete(PkiServPid, Rest, Failures).

%% /dj/key/export (POST)

key_export_post(Options, PkiServPid, <<"all">>) ->
    {ok, Nyms} = local_pki_serv:all_nyms(PkiServPid),
    key_export_post(Options, PkiServPid, Nyms);
key_export_post(Options, PkiServPid, Nyms) when is_list(Nyms) ->
    TempFilename = "keys-" ++ ?i2l(erlang:unique_integer([positive])) ++ ".bin",
    {value, {_, TempDir}} = lists:keysearch(temp_dir, 1, Options),
    AbsFilename = filename:join([TempDir, TempFilename]),
    UriPath = filename:join(["temp", TempFilename]),
    {ok, File} = file:open(AbsFilename, [write, binary]),
    key_export(PkiServPid, Nyms, UriPath, File, erlang:md5_init());
key_export_post(_Options, _PkiServPid, _Nyms) ->
    {error, bad_request, "Invalid nyms"}.

key_export(_PkiServPid, [], UriPath, File, MD5Context) ->
    Digest = erlang:md5_final(MD5Context),
    DigestSize = size(Digest),
    DigestPacket = <<0:16/unsigned-integer,
                     DigestSize:16/unsigned-integer, Digest/binary>>,
    ok = file:write(File, DigestPacket),
    ok = file:close(File),
    {ok, {format, ?l2b(UriPath)}};
key_export(PkiServPid, [Nym|Rest], UriPath, File, MD5Context)
  when is_binary(Nym) ->
    case local_pki_serv:read(PkiServPid, Nym) of
        {ok, PublicKey} ->
            PublicKeyBin = elgamal:public_key_to_binary(PublicKey),
            PublicKeyBinSize = size(PublicKeyBin),
            Packet = <<PublicKeyBinSize:16/unsigned-integer, PublicKeyBin/binary>>,
            ok = file:write(File, Packet),
            NewMD5Context = erlang:md5_update(MD5Context, Packet),
            key_export(PkiServPid, Rest, UriPath, File, NewMD5Context);
        {error, no_such_key} ->
            key_export(PkiServPid, Rest, UriPath, File, MD5Context)
    end;
key_export(_PkiServPid, _Nyms, _UriPath, _File, _MD5Context) ->
    {error, bad_request, "Invalid nyms"}.

%% /dj/key/import (POST)

key_import_post(PkiServPid, Filename) ->
    {ok, File} = file:open(Filename, [read, binary]),
    key_import(PkiServPid, File, erlang:md5_init()).

key_import(PkiServPid, File, MD5Context) ->
    case file:read(File, 2) of
        {ok, <<0:16/unsigned-integer>>} ->
            case file:read(File, 2) of
                {ok, <<DigestSize:16/unsigned-integer>>} ->
                    case file:read(File, DigestSize) of
                        {ok, Digest} ->
                            case erlang:md5_final(MD5Context) of
                                Digest ->
                                    ok = file:close(File),
                                    ok_204;
                                _ ->
                                    ok = file:close(File),
                                    {error, bad_request, "Invalid format"}
                            end;
                        _ ->
                            ok = file:close(File),
                            {error, bad_request, "Invalid format"}
                    end;
                _ ->
                    ok = file:close(File),
                    {error, bad_request, "Invalid format"}
            end;
        {ok, <<PublicKeyBinSize:16/unsigned-integer>>} ->
            case file:read(File, PublicKeyBinSize) of
                {ok, PublicKeyBin} ->
                    PublicKey =
                        try
                            elgamal:binary_to_public_key(PublicKeyBin)
                        catch
                            _:_ ->
                                bad_key
                        end,
                    case PublicKey of
                        bad_key ->
                            ok = file:close(File),
                            {error, bad_request, "Invalid format"};
                        _ ->
                            case local_pki_serv:update(PkiServPid, PublicKey) of
                                ok ->
                                    NewMD5Context =
                                        erlang:md5_update(MD5Context, PublicKeyBin),
                                    key_import(PkiServPid, File, NewMD5Context);
                                {error, permission_denied} ->
                                    {error, no_access}
                            end
                    end;
                _ ->
                    {error, bad_request, "Invalid format"}
            end;
        eof ->
            ok = file:close(File),
            ok_204;
        {error, _Reason} ->
            {error, bad_request, "Invalid format"}
    end.
