-module(pop3_serv).
-export([start_link/5]).

%% DEBUG: mpop --debug --host=127.0.0.1 --port=29900 --deliver=mbox,fnutt --keep=on --auth=user --user=alice --tls=on --tls-starttls=off --tls-certcheck=off --passwordeval='echo "baz"'

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("mail/include/pop3lib.hrl").
-include_lib("mail/include/maildrop_serv.hrl").

-record(state,
        {nym :: binary(),
         password_digest :: binary(),
         login_nym = not_set :: binary() | not_set,
         check_credentials :: function(),
         maildrop_serv_pid = not_set :: pid() | not_set,
         temp_dir :: binary()}).

%% Exported: start_link

start_link(Nym, PasswordDigest, TempDir, CertFilename, {IpAddress, Port}) ->
    PatchInitialServletState =
        fun(State) ->
                receive
                    {neighbour_workers, NeighbourWorkers} ->
                        [MaildropServPid] =
                            supervisor_helper:get_selected_worker_pids(
                              [maildrop_serv], NeighbourWorkers),
                        State#state{maildrop_serv_pid = MaildropServPid}
                end
        end,
    Options =
        #pop3lib_options{
           cert_filename = CertFilename,
           timeout = 10 * 60 * 1000,
           greeting = <<"[127.0.0.1] POP3 server ready">>,
           initial_servlet_state =
               #state{nym = Nym,
                      password_digest = PasswordDigest,
                      check_credentials = fun check_credentials/3,
                      temp_dir = TempDir},
           servlets = [#servlet{command = stat, handler = fun stat/2},
                       #servlet{command = list, handler = fun list/2},
                       #servlet{command = retr, handler = fun retr/2},
                       #servlet{command = dele, handler = fun dele/2},
                       #servlet{command = rset, handler = fun rset/2},
                       #servlet{command = quit, handler = fun quit/2},
                       #servlet{command = top, handler = fun top/2},
                       #servlet{command = uidl, handler = fun uidl/2},
                       #servlet{command = user, handler = fun user/2},
                       #servlet{command = pass, handler = fun pass/2},
                       #servlet{command = capa, handler = fun capa/2}],
           patch_initial_servlet_state = PatchInitialServletState,
           temp_dir = TempDir},
    ?daemon_log_tag_fmt(system, "POP3 server starting for ~s on ~s:~w",
                        [Nym, inet:ntoa(IpAddress), Port]),
    pop3lib:start_link(IpAddress, Port, Options).

check_credentials(#state{nym = Nym, password_digest = PasswordDigest}, Nym,
                  Password) ->
    player_crypto:check_digested_password(Password, PasswordDigest);
check_credentials(_State, _Nym, _Password) ->
    false.

%% https://tools.ietf.org/html/rfc1939#page-6
stat(#channel{servlet_state =
                  #state{maildrop_serv_pid = MaildropServPid}} = Channel,
     Args) ->
    ?dbg_log({stat, Channel, Args}),
    case Args of
        [] ->
            {N, Octets} = get_statistics(MaildropServPid),
            DropListing= io_lib:format("~w ~w octets", [N, Octets]),
            #response{info = ?l2b(DropListing)};
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-6
list(#channel{servlet_state =
                  #state{maildrop_serv_pid = MaildropServPid}} = Channel,
     Args) ->
    ?dbg_log({list, Channel, Args}),
    case Args of
        [MessageNumber] ->
            case convert_to_integer(MessageNumber) of
                {ok, MessageNumberInteger} ->
                    case maildrop_serv:read(
                           MaildropServPid, MessageNumberInteger) of
                        {ok, #mail{octets = Octets}} ->
                            ScanListing =
                                io_lib:format("~w ~w", [MessageNumberInteger,
                                                        Octets]),
                            #response{info = ?l2b(ScanListing)};
                        {error, Reason} ->
                            #response{
                               status = err,
                               info = maildrop_serv:strerror(Reason)}
                    end;
                {error, not_integer} ->
                    #response{status = err, info = <<"invalid message number">>}
            end;
        [] ->
            {N, TotalOctets, ScanListings} =
                maildrop_serv:foldl(
                  MaildropServPid,
                  fun(#mail{message_number = MessageNumber,
                            octets = Octets,
                            deleted = false},
                      {N, SumOctets, AllScanListings}) ->
                          ScanListing =
                              io_lib:format("~w ~w", [MessageNumber, Octets]),
                          {N + 1, SumOctets + Octets,
                           [?l2b(ScanListing)|AllScanListings]};
                     (_Mail, Acc) ->
                          Acc
                  end,
                  {0, 0, []}),
            MaildropSummary =
                io_lib:format("~w messages (~w octets)", [N, TotalOctets]),
            #response{
               info = ?l2b(MaildropSummary),
               body = lists:reverse(ScanListings)};
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-8
retr(#channel{servlet_state =
                  #state{maildrop_serv_pid = MaildropServPid}} = Channel,
     Args) ->
    ?dbg_log({retr, Channel, Args}),
    case Args of
        [MessageNumber] ->
            case convert_to_integer(MessageNumber) of
                {ok, MessageNumberInteger} ->
                    case maildrop_serv:read(
                           MaildropServPid, MessageNumberInteger) of
                        {ok, #mail{octets = Octets, filename = Filename}} ->
                            Info =
                                io_lib:format("~w ~w",
                                              [MessageNumberInteger, Octets]),
                            #response{info = ?l2b(Info),
                                      body = {file, Filename}};
                        {error, Reason} ->
                            #response{
                               status = err,
                               info = maildrop_serv:strerror(Reason)}
                    end;
                {error, not_integer} ->
                    #response{status = err, info = <<"invalid message number">>}
            end;
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-8
dele(#channel{servlet_state =
                  #state{maildrop_serv_pid = MaildropServPid}} = Channel,
     Args) ->
    ?dbg_log({dele, Channel, Args}),
    case Args of
        [MessageNumber] ->
            case convert_to_integer(MessageNumber) of
                {ok, MessageNumberInteger} ->
                    case maildrop_serv:delete(
                           MaildropServPid, MessageNumberInteger) of
                        ok ->
                            #response{info = <<"message deleted">>};
                        {error, Reason} ->
                            #response{
                               status = err,
                               info = maildrop_serv:strerror(Reason)}
                    end;
                {error, not_integer} ->
                    #response{status = err, info = <<"invalid message number">>}
            end;
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-10
rset(#channel{
        servlet_state = #state{maildrop_serv_pid = MaildropServPid}} = Channel,
     Args) ->
    ?dbg_log({rset, Channel, Args}),
    case Args of
        [] ->
            ok = maildrop_serv:undelete(MaildropServPid),
            {N, Octets} = get_statistics(MaildropServPid),
            Info = io_lib:format("maildrop has ~w messages (~w)", [N, Octets]),
            #response{info = ?l2b(Info)};
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-11
quit(#channel{mode = Mode,
              servlet_state =
                  #state{maildrop_serv_pid = MaildropServPid}} = Channel,
     Args) ->
    ?dbg_log({quit, Channel, Args}),
    case Args of
        [] ->
            if
                Mode == transaction ->
                    case maildrop_serv:unlock(MaildropServPid) of
                        ok ->
                            #response{action = break,
                                      info = <<"POP3 server signing off">>};
                        {error, Reason} ->
                            #response{
                               status = err,
                               info = maildrop_serv:strerror(Reason)}
                    end;
                true ->
                    #response{action = break,
                              info = <<"POP3 server signing off">>}
            end;
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-11
top(#channel{servlet_state =
                 #state{maildrop_serv_pid = MaildropServPid}} = Channel,
    Args) ->
    ?dbg_log({dele, Channel, Args}),
    case Args of
        [MessageNumber, N] ->
            case convert_to_integers([MessageNumber, N]) of
                {ok, [MessageNumberInteger, NInteger]} ->
                    case maildrop_serv:read(
                           MaildropServPid, MessageNumberInteger) of
                        {ok, #mail{filename = Filename}} ->
                            #response{body = {file, Filename, NInteger}};
                        {error, Reason} ->
                            #response{
                               status = err,
                               info = maildrop_serv:strerror(Reason)}
                    end;
                {error, not_integers} ->
                    #response{status = err, info = <<"invalid message number">>}
            end;
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-11
uidl(#channel{servlet_state =
                  #state{maildrop_serv_pid = MaildropServPid}} = Channel,
     Args) ->
    ?dbg_log({uidl, Channel, Args}),
    case Args of
        [MessageNumber] ->
            case convert_to_integer(MessageNumber) of
                {ok, MessageNumberInteger} ->
                    case maildrop_serv:read(
                           MaildropServPid, MessageNumberInteger) of
                        {ok, #mail{unique_id = UniqueId}} ->
                            UniqueIdListing =
                                io_lib:format("~w ~s", [MessageNumberInteger,
                                                        UniqueId]),
                            #response{body = [?l2b(UniqueIdListing)]};
                        {error, Reason} ->
                            #response{
                               status = err,
                               info = maildrop_serv:strerror(Reason)}
                    end;
                {error, not_integer} ->
                    #response{status = err, info = <<"invalid message number">>}
            end;
        [] ->
            UniqueIdListings =
                maildrop_serv:foldl(
                  MaildropServPid,
                  fun(#mail{message_number = MessageNumber,
                            unique_id = UniqueId, deleted = false},
                      Acc) ->
                          UniqueIdListing =
                              io_lib:format("~w ~s", [MessageNumber, UniqueId]),
                          [?l2b(UniqueIdListing)|Acc];
                     (_, Acc) ->
                          Acc
                  end, []),
            #response{body = lists:reverse(UniqueIdListings)};
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-13
user(#channel{servlet_state = State} = Channel, Args) ->
    ?dbg_log({user, Channel, Args}),
    case Args of
        [LoginNym] ->
            #response{
               info = <<"proceed with password">>,
               channel = Channel#channel{
                           mode = password,
                           servlet_state =
                               State#state{login_nym = LoginNym}}};
        _ ->
            #response{status = err, info = <<"invalid argument(s)">>}
    end.

%% https://tools.ietf.org/html/rfc1939#page-14
pass(#channel{
        servlet_state =
            #state{login_nym = LoginNym,
                   maildrop_serv_pid = MaildropServPid} = State} = Channel,
     Args) ->
    ?dbg_log({pass, Channel, Args}),
    case Args of
        [LoginPassword] ->
            case check_credentials(State, LoginNym, LoginPassword) of
                true ->
                    case maildrop_serv:lock(MaildropServPid)  of
                        ok ->
                            #response{
                               info = <<"maildrop locked and ready">>,
                               channel =
                                   Channel#channel{
                                     mode = transaction, authorized = true}};
                        {error, Reason} ->
                            #response{
                               status = err,
                               info = maildrop_serv:strerror(Reason),
                               channel =
                                   Channel#channel{
                                     mode = authorization,
                                     servlet_state =
                                         State#state{login_nym = not_set}}}
                    end;
                false ->
                    #response{
                       status = err,
                       info = <<"invalid username or password">>,
                       channel =
                           Channel#channel{
                             mode = authorization,
                             servlet_state = State#state{login_nym = not_set}}}
            end;
        _ ->
            #response{status = err,
                       info = <<"invalid argument(s)">>,
                       channel = Channel#channel{
                                   mode = authorization,
                                   servlet_state =
                                       State#state{login_nym = not_set}}}
    end.

%% https://tools.ietf.org/html/rfc1939#page-14
capa(Channel, Args) ->
    ?dbg_log({capa, Channel, Args}),
    #response{info = <<"list of capabilities follows">>,
              body = [<<"UIDL">>, <<"USER">>, <<"SASL PLAIN">>]}.

%%
%% Utilities
%%

convert_to_integers(List) ->
  convert_to_integers(List, []).

convert_to_integers([], Integers) ->
    {ok, lists:reverse(Integers)};
convert_to_integers([String|Rest], Integers) ->
    try
      convert_to_integers(Rest, [?b2i(String)|Integers])
    catch
        _:_ ->
            {error, not_integers}
    end.

convert_to_integer(String) ->
    try
        {ok, ?b2i(String)}
    catch
        _:_ ->
            {error, not_integer}
    end.

get_statistics(MaildropServPid) ->
    maildrop_serv:foldl(
      MaildropServPid,
      fun(#mail{octets = Octets, deleted = false}, {N, SumOctets}) ->
              {N + 1, SumOctets + Octets};
         (_Mail, Acc) ->
              Acc
      end,
      {0, 0}).
