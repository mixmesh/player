-module(rest_normal_server).
-export([start_link/4, parse_key_bundle/1]).
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

start_link(Nym, HttpPassword, HttpCertFilename, {IfAddr,Port}) ->
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
	  {?MODULE, handle_http_request, []}},
	 %% FIXME: we should probably only allow digest!
	 {access, [%% {basic,"",Nym,HttpPassword,"obscrete"},
		   {digest,"",Nym,HttpPassword,"obscrete"}]},
	 {verify, verify_none},
	 {ifaddr, IfAddr},
	 {certfile, HttpCertFilename},
	 {nodelay, true},
	 {reuseaddr, true},
	 {idle_timeout, IdleTimeout},
	 {send_timeout, SendTimeout} | S01],
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

handle_http_get(Socket, Request, _Options, _Url, Tokens, _Body, v1) ->
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
	    rest_util:response(Socket, Request,
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
	    rest_util:response(Socket,Request,rest_util:html_doc(rest_util:html_table(Tab)));
	_ ->
	    ?dbg_log_fmt("~p not found", [Tokens]),
	    rest_util:response(Socket, Request, {error, not_found})
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
                          base64:encode(
                            elgamal:public_key_to_binary(PublicKey))
                  end, PublicKeys),
            rest_util:response(Socket, Request, {ok, {format, JsonTerm}});
        ["key", Nym] ->
            [PkiServPid] = get_worker_pids([pki_serv], Options),
            NymBin = ?l2b(Nym),
            case local_pki_serv:read(PkiServPid, NymBin) of
                {ok, PublicKey} ->
                    JsonTerm = base64:encode(
                                 elgamal:public_key_to_binary(PublicKey)),
                    rest_util:response(Socket, Request, {ok, {format, JsonTerm}});
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
                    rest_util:response(Socket, Request, key_put(PkiServPid, JsonTerm))
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
                    rest_util:response(Socket, Request, get_config_post(JsonTerm))
            end;
        ["edit-config"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    rest_util:response(Socket, Request, edit_config_post(JsonTerm))
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
                             key_export_post(PkiServPid, JsonTerm))
            end;
        ["key", "import"] ->
            case rest_util:parse_body(Request, Body,
                            [{jsone_options, [{object_format, proplist}]}]) of
                {error, _Reason} ->
                    rest_util:response(Socket, Request,
                             {error, bad_request, "Invalid JSON format"});
                JsonTerm ->
                    [PkiServPid] = get_worker_pids([pki_serv], Options),
                    rest_util:response(Socket, Request,
                             key_import_post(PkiServPid, JsonTerm))
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
                            {ok, DecryptedSecretKey} = shared_decrypt_secret_key(Value),
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
    key_filter_post(PkiServPid, JsonTerm, {[], 100}).

key_filter_post(_PkiServPid, SubStringNyms, {PublicKeysAcc, N})
  when SubStringNyms == [] orelse N == 0 ->
    JsonTerm =
        lists:map(
          fun(PublicKey) ->
                  base64:encode(elgamal:public_key_to_binary(PublicKey))
          end, lists:usort(
                 fun(PublicKey1, PublicKey2) ->
                         PublicKey1#pk.nym < PublicKey2#pk.nym
                 end, PublicKeysAcc)),
    {ok, {format, JsonTerm}};
key_filter_post(PkiServPid, [SubStringNym|Rest], {PublicKeysAcc, N})
  when is_binary(SubStringNym) ->
    {ok, PublicKeys} =
        local_pki_serv:list(PkiServPid, {substring, SubStringNym}, N),
    key_filter_post(PkiServPid, Rest, {PublicKeys ++ PublicKeysAcc, N - 1});
key_filter_post(_PkiServPid, _SubStringNyms, {_PublicKeysAcc, _N}) ->
    {error, bad_request, "Invalid filter"}.

%% /dj/key/delete (POST)

key_delete_post(PkiServPid, Nyms) when is_list(Nyms) ->
    key_delete_post(PkiServPid, Nyms, []);
key_delete_post(_PkiServPid, _JsonTerm) ->
    {error, bad_request, "Invalid nym"}.

key_delete_post(_PkiServPid, [], Failures) ->
    JsonTerm =
        lists:map(
          fun({Nym, Reason}) ->
                  [{<<"nym">>, Nym},
                   {<<"reason">>, local_pki_serv:strerror(Reason)}]
          end, Failures),
    {ok, {format, JsonTerm}};
key_delete_post(PkiServPid, [Nym|Rest], Failures)
  when is_binary(Nym) ->
    case local_pki_serv:delete(PkiServPid, Nym) of
        ok ->
            key_delete_post(PkiServPid, Rest, Failures);
        {error, Reason} ->
            key_delete_post(PkiServPid, Rest,
                            [{Nym, Reason}|Failures])
    end;
key_delete_post(PkiServPid, [_|Rest], Failures) ->
    key_delete_post(PkiServPid, Rest, Failures).

%% /dj/key/export (POST)

key_export_post(PkiServPid, Nyms) ->
    key_export_post(PkiServPid, Nyms, []).

key_export_post(_PkiServPid, [], PublicKeys) ->
    KeyBundle =
        lists:map(
          fun(PublicKey) ->
                  PublicKeyBin = elgamal:public_key_to_binary(PublicKey),
                  PublicKeyBinSize = size(PublicKeyBin),
                  <<PublicKeyBinSize:16/unsigned-integer, PublicKeyBin/binary>>
          end, PublicKeys),
    {ok, {format, base64:encode(?l2b(KeyBundle))}};
key_export_post(PkiServPid, [Nym|Rest], PublicKeys)
  when is_binary(Nym) ->
    case local_pki_serv:read(PkiServPid, Nym) of
        {ok, PublicKey} ->
            key_export_post(PkiServPid, Rest, [PublicKey|PublicKeys]);
        {error, no_such_key} ->
            key_export_post(PkiServPid, Rest, PublicKeys)
    end;
key_export_post(_PkiServPid, _Nyms, _PublicKeys) ->
    {error, bad_request, "Invalid list of nyms"}.

%% /dj/key/import (POST)

key_import_post(PkiServPid, KeyBundle) when is_binary(KeyBundle) ->
    DecodedKeyBundle =
        try
            base64:decode(KeyBundle)
        catch
            _:_ ->
                not_base64
        end,
    case DecodedKeyBundle of
        not_base64 ->
            {error, bad_request, "Invalid key bundle"};
        _ ->
            key_import_post(PkiServPid, DecodedKeyBundle, [])
    end;
key_import_post(_PkiServPid, _JsonTerm) ->
    {error, bad_request, "Invalid key bundle"}.

key_import_post(PkiServPid, <<>>, PublicKeys) ->
    update_public_keys(PkiServPid, PublicKeys);
key_import_post(PkiServPid,
                <<PublicKeyBinSize:16/unsigned-integer,
                  PublicKeyBin:PublicKeyBinSize/binary,
                  Rest/binary>>, PublicKeys) ->
    PublicKey =
        try
            elgamal:binary_to_public_key(PublicKeyBin)
        catch
            _:_ ->
                bad_key
        end,
    case PublicKey of
        bad_key ->
            {error, bad_request, "Invalid key bundle"};
        _ ->
            key_import_post(PkiServPid, Rest, [PublicKey|PublicKeys])
    end;
key_import_post(_PkiServPid, _KeyBundle, _PublicKeys) ->
    {error, bad_request, "Invalid key bundle"}.

update_public_keys(_PkiServPid, []) ->
    ok_204;
update_public_keys(PkiServPid, [PublicKey|Rest]) ->
    case local_pki_serv:update(PkiServPid, PublicKey) of
        ok ->
            update_public_keys(PkiServPid, Rest);
        {error, permission_denied} ->
            {error, no_access}
    end.

%% Exported: parse_key_bundle

parse_key_bundle(KeyBundle) ->
    try
        parse_key_bundle(KeyBundle, [])
    catch
        _:_ ->
            bad_format
    end.

parse_key_bundle(<<>>, Acc) ->
    Acc;
parse_key_bundle(<<PublicKeyBinSize:16/unsigned-integer,
                   PublicKeyBin:PublicKeyBinSize/binary,
                   Rest/binary>>, Acc) ->
    PublicKey = elgamal:binary_to_public_key(PublicKeyBin),
    parse_key_bundle(Rest, [PublicKey|Acc]).
