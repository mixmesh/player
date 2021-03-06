-module(smtp_serv).
-export([start_link/6]).
-export([check_credentials/4]).
-export([helo/2, ehlo/2, auth/2, mail/2, rcpt/2, data/2, rset/2, vrfy/2, expn/2,
         help/2, quit/2, any/2]).

%% DEBUG: swaks --from alice@mixmesh.net --to alice@mixmesh.net --server 127.0.0.1:19900 --auth LOGIN --auth-user alice --tls-on-connect --auth-password baz --body "FOO"

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("mail/include/smtplib.hrl").

-record(state,
        {nym :: binary(),
         password_digest :: binary(),
         login_state = waiting_for_nym :: waiting_for_nym |
                                           {waiting_for_password, binary()},
         check_credentials :: function(),
         reverse_path = not_set :: binary() | not_set,
         forward_path = not_set :: binary() | not_set,
         message_size = 64 * 1024 :: integer(),
         player_serv_pid = not_set :: pid() | not_set,
         temp_dir :: binary(),
         simulated :: boolean()}).

%%
%% Exported: start_link
%%

start_link(Nym, PasswordDigest, TempDir, CertFilename, {IpAddress, Port},
           Simulated) ->
    PatchInitialServletState =
        fun(State) ->
                receive
                    {neighbour_workers, NeighbourWorkers} ->
                        [PlayerServPid] =
                            supervisor_helper:get_selected_worker_pids(
                              [player_serv], NeighbourWorkers),
                        State#state{player_serv_pid = PlayerServPid}
                end
        end,
    Options =
        #smtplib_options{
           cert_filename = CertFilename,
           timeout = 10 * 60 * 1000,
           greeting = <<"[127.0.0.1] ESMTP server ready">>,
           authenticate = yes,
           initial_servlet_state =
               #state{nym = Nym,
                      password_digest = PasswordDigest,
                      check_credentials = fun ?MODULE:check_credentials/4,
                      temp_dir = TempDir,
                      simulated = Simulated},
           servlets = [#servlet{command = helo, handler = fun ?MODULE:helo/2},
                       #servlet{command = ehlo, handler = fun ?MODULE:ehlo/2},
                       #servlet{command = auth, handler = fun ?MODULE:auth/2},
                       #servlet{command = mail, handler = fun ?MODULE:mail/2},
                       #servlet{command = rcpt, handler = fun ?MODULE:rcpt/2},
                       #servlet{command = data, handler = fun ?MODULE:data/2},
                       #servlet{command = rset, handler = fun ?MODULE:rset/2},
                       #servlet{command = vrfy, handler = fun ?MODULE:vrfy/2},
                       #servlet{command = expn, handler = fun ?MODULE:expn/2},
                       #servlet{command = help, handler = fun ?MODULE:help/2},
                       #servlet{command = quit, handler = fun ?MODULE:quit/2},
                       #servlet{command = any, handler = fun ?MODULE:any/2}],
           patch_initial_servlet_state = PatchInitialServletState,
           temp_dir = TempDir},
    ?daemon_log_tag_fmt(system, "SMTP server starting for ~s on ~s:~w",
                        [Nym, inet:ntoa(IpAddress), Port]),
    smtplib:start_link(IpAddress, Port, Options).

check_credentials(#state{nym = Nym, password_digest = PasswordDigest},
                  _Autczid, Nym, Password) ->
    player_crypto:check_digested_password(Password, PasswordDigest);
check_credentials(_State, _Autczid, _Authcid, _Password) ->
    false.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.1
helo(#channel{servlet_state = ServletState} = Channel, Args) ->
    ?dbg_log({helo, Channel, Args}),
    case Args of
        [] ->
            #response{status = 501, info = <<"domain address required">>};
        [_] ->
            NewServletState =
                ServletState#state{reverse_path = not_set,
                                   forward_path = not_set},
            #response{
               channel = Channel#channel{mode = helo,
                                         servlet_state = NewServletState}};
        _ ->
            #response{status = 500,
                      info = <<"syntax error, command unrecognized">>}
    end.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.1
ehlo(#channel{servlet_state = ServletState} = Channel, Args) ->
    ?dbg_log({ehlo, Channel, Args}),
    case Args of
        [] ->
            #response{status = 501, info = <<"domain address required">>};
        [_Domain] ->
            NewServletState =
                ServletState#state{reverse_path = not_set,
                                   forward_path = not_set},
            #response{
               replies =
                   [%% https://tools.ietf.org/html/rfc2821#section-3.1
                    {250, <<"[127.0.0.1] at your service">>},
                    %% https://tools.ietf.org/html/rfc1870
                    {250,
                     ?l2b([<<"SIZE ">>,
                           ?i2b(NewServletState#state.message_size)])},
                    %% https://tools.ietf.org/html/rfc6152
                    {250, <<"8BITMIME">>},
                    %% https://tools.ietf.org/html/rfc6531
                    {250, <<"SMTPUTF8">>},
                    %% https://www.samlogic.net/articles/smtp-commands-reference-auth.htm
                    {250, <<"AUTH PLAIN LOGIN">>}],
               channel = Channel#channel{
                           mode = helo, servlet_state = NewServletState}};
        _ ->
            #response{status = 500,
                      info = <<"syntax error, command unrecognized">>}
    end.

%% https://www.samlogic.net/articles/smtp-commands-reference-auth.htm
auth(#channel{
        servlet_state =
            #state{
               check_credentials = CheckCredentials} = ServletState} = Channel,
     Args) ->
    ?dbg_log({auth, Channel, Args}),
    case mail_util:get_arg(Args) of
        {ok, <<"PLAIN">>, [Credentials]} ->
            %% Zm9vAGJhcgBiYXo= equals "foo\0bar\0baz"
            case string:lexemes(base64:decode(Credentials), "\0") of
                [Authcid, Password] ->
                    case CheckCredentials(
                           ServletState, none, Authcid, Password) of
                        true ->
                            #response{
                               status = 235,
                               info = <<"authentication successful">>,
                               channel =
                                   Channel#channel{
                                     mode = helo, authenticated = true}};
                        false ->
                            #response{
                               status = 535,
                               info =
                                   <<"authentication credentials invalid">>}
                    end;
                _ ->
                    #response{status = 500,
                              info = <<"syntax error, command unrecognized">>}
            end;
        {ok, <<"LOGIN">>, []} ->
            NewServletState =
                ServletState#state{login_state = waiting_for_nym},
            #response{
               status = 334,
               info = <<"VXNlcm5hbWU6">>,
               channel = Channel#channel{
                           mode = auth, servlet_state = NewServletState}};
        _ ->
            #response{
               status = 500,
               info = <<"syntax error, command unrecognized">>}
    end.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.2
mail(#channel{servlet_state = ServletState} = Channel, Args) ->
    ?dbg_log({mail, Channel, Args}),
    case mail_util:get_arg(<<"FROM">>, ":", fun mail_util:strip_path/1, Args) of
        {ok, ReversePath, RemainingArgs} ->
            case mail_util:get_arg(<<"SIZE">>, "=", integer, RemainingArgs) of
                {ok, SizeValue, _} ->
                    case SizeValue > ServletState#state.message_size of
                        true ->
                            #response{status = 552,
                                      info = <<"too much mail data">>};
                        false ->
                            NewServletState =
                                ServletState#state{reverse_path = ReversePath,
                                                   forward_path = not_set},
                            #response{
                               channel = Channel#channel{
                                           mode = mail,
                                           servlet_state =
                                               NewServletState}}
                    end;
                {error, no_arguments} ->
                    NewServletState =
                        ServletState#state{reverse_path = ReversePath,
                                           forward_path = not_set},
                    #response{
                       channel =
                           Channel#channel{mode = mail,
                                           servlet_state = NewServletState}};
                _ ->
                    #response{status = 500,
                              info = <<"syntax error, command unrecognized">>}
            end;
        _ ->
            #response{status = 500,
                      info = <<"syntax error, command unrecognized">>}
    end.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.3
rcpt(#channel{servlet_state = ServletState} = Channel, Args) ->
    ?dbg_log({rcpt, Channel, Args}),
    case mail_util:get_arg(<<"TO">>, ":", fun mail_util:strip_path/1, Args) of
        {ok, ForwardPath, _RemainingArgs} ->
            NewServletState = ServletState#state{forward_path = ForwardPath},
            #response{
               channel = Channel#channel{mode = rcpt,
                                         servlet_state = NewServletState}};
        {error, _Reason} ->
            #response{
               status = 500,
               info = <<"syntax error, command unrecognized">>}
    end.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.4
data(#channel{
        servlet_state =
            #state{player_serv_pid = PlayerServPid } = ServletState} = Channel,
     #data{headers = _Headers, filename = Filename, size = Size} = Data) ->
    ?dbg_log({data, Channel, Data}),
    if
        Size > ServletState#state.message_size ->
            #response{status = 550, info = <<"too much mail data">>};
        true ->
            case ServletState of
                #state{reverse_path = not_set} ->
                    #response{status = 503, info = <<"bad command sequence">>};
                #state{forward_path = not_set} ->
                    #response{status = 554, info = <<"no valid recipients">>};
                #state{forward_path = ForwardPath} ->
                    TargetNym =
                        re:replace(ForwardPath, <<"@.*">>, <<"">>,
                                   [{return, binary}]),
                    {ok, Payload} = file:read_file(Filename),
                    ?dbg_log({send_mail, ServletState#state.nym, TargetNym,
                              Filename}),
                    case player_serv:send_message(
                           PlayerServPid, TargetNym, Payload) of
                        ok ->
                            #response{channel = Channel#channel{mode = helo}};
                        {error, Reason} ->
                            ?error_log({send_message, Reason}),
                            #response{status = 550,
                                      info = <<"message could not be sent">>}
                    end
            end
    end.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.5
rset(#channel{servlet_state = ServletState} = Channel, Args) ->
    ?dbg_log({rset, Channel, Args}),
    NewServletState =
        ServletState#state{reverse_path = not_set, forward_path = not_set},
    #response{channel = Channel#channel{mode = helo,
                                        servlet_state = NewServletState}}.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.6
vrfy(Channel, Args) ->
      ?dbg_log({vrfy, Channel, Args}),
      #response{status = 502, info = <<"command not implemented">>}.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.7
expn(Channel, Args) ->
    ?dbg_log({expn, Channel, Args}),
    #response{status = 502, info = <<"command not implemented">>}.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.8
help(Channel, Args) ->
    ?dbg_log({help, Channel, Args}),
    #response{status = 502, info = <<"command not implemented">>}.

%% https://tools.ietf.org/html/rfc2821#section-4.1.1.9
quit(Channel, Args) ->
    ?dbg_log({quit, Channel, Args}),
    #response{action = break,
              status = 221,
              info = <<"service closing transmission channel">>}.

any(#channel{
       mode = Mode,
       servlet_state =
           #state{
              login_state = LoginState,
              check_credentials = CheckCredentials} = ServletState} = Channel,
    Line) ->
    ?dbg_log({any, Channel, Line}),
    case {Mode, LoginState} of
        %% https://www.samlogic.net/articles/smtp-commands-reference-auth.htm
        {auth, waiting_for_nym} ->
            Autczid = base64:decode(string:chomp(Line)),
            NewServletState =
                ServletState#state{
                  login_state = {waiting_for_password, Autczid}},
            #response{
               status = 334,
               info = <<"UGFzc3dvcmQ6">>,
               channel = Channel#channel{servlet_state = NewServletState}};
        %% https://www.samlogic.net/articles/smtp-commands-reference-auth.htm
        {auth, {waiting_for_password, Autczid}} ->
            Password = base64:decode(string:chomp(Line)),
            case CheckCredentials(ServletState, none, Autczid, Password) of
                true ->
                    #response{
                       status = 235,
                       info = <<"authentication successful">>,
                       channel =
                           Channel#channel{mode = helo,
                                           authenticated = true}};
                false ->
                    #response{
                       status = 535,
                       info = <<"authentication credentials invalid">>}
            end;
        _ ->
            #response{status = 502, info = <<"command not implemented">>}
  end.
