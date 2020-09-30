-module(player_sup).
-behaviour(supervisor).
-export([start_link/0]).
-export([attach_child/3]).
-export([init/1]).

%% Exported: start_link

start_link() ->
    case supervisor:start_link(?MODULE, []) of
        {ok, Pid} ->
            case supervisor:which_children(Pid) of
                [] ->
                    {ok, Pid};
                Children ->
                    ok = attach_child(player_serv, [mail_serv, maildrop_serv],
                                      Children),
                    ok = attach_child(player_sync_serv, player_serv, Children),
                    ok = attach_child(smtp_proxy_serv, player_serv, Children),
                    ok = attach_child(pop3_proxy_serv, maildrop_serv, Children),
                    {ok, Pid}
            end;
        Error ->
            Error
    end.

attach_child(SourceId, TargetId, Children) ->
    {value, {SourceId, SourcePid, _, _}} =
        lists:keysearch(SourceId, 1, Children),
    if
        is_list(TargetId) ->
            Targets =
                lists:map(fun(Id) ->
                                  {value, {Id, Pid, _, _}} =
                                      lists:keysearch(Id, 1, Children),
                                  {Id, Pid}
                          end, TargetId),
            SourcePid ! {sibling_pid, Targets},
            ok;
        true ->
            {value, {TargetId, TargetPid, _, _}} =
                lists:keysearch(TargetId, 1, Children),
            SourcePid ! {sibling_pid, TargetId, TargetPid},
            ok
    end.

%% Exported: init

init([]) ->
    case config:lookup([player, enabled]) of
        true ->
            [Name, Password, {SyncAddress, SyncPort}, TempDir, Spiridon,
             Maildrop, SmtpProxy, Pop3Proxy] =
                config:lookup_children(
                  [username, password, 'sync-address', 'temp-dir', spiridon,
                   maildrop, 'smtp-proxy', 'pop3-proxy'],
                  config:lookup([player])),
            [F] = config:lookup_children([f], Spiridon),
            [SpoolerDir] = config:lookup_children(['spooler-dir'], Maildrop),
            [{SmtpAddress, SmtpPort}] =
                config:lookup_children([address], SmtpProxy),
            [{Pop3Address, Pop3Port}] =
                config:lookup_children([address], Pop3Proxy),
            PlayerServSpec =
                #{id => player_serv,
                  start => {player_serv, start_link,
                            [Name, SyncAddress, SyncPort, TempDir,
                             not_set, not_set, false]}},
            PlayerSyncServSpec =
                #{id => player_sync_serv,
                  start => {player_sync_serv, start_link,
                            [Name, SyncAddress, SyncPort, F, false]}},
            MailServSpec =
                #{id => mail_serv,
                  start => {mail_serv, start_link,
                            [Name, SmtpAddress, SmtpPort]}},
            MaildropServSpec =
                #{id => maildrop_serv,
                  start => {maildrop_serv, start_link, [SpoolerDir]}},
            SmtpProxyServSpec =
                #{id => smtp_proxy_serv,
                  start => {smtp_proxy_serv, start_link,
                            [Name, Password, TempDir, SmtpAddress,
                             SmtpPort]}},
            Pop3ProxyServSpec =
                #{id => pop3_proxy_serv,
                  start => {pop3_proxy_serv, start_link,
                            [Name, Password, TempDir, Pop3Address,
                             Pop3Port]}},
            {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                               PlayerSyncServSpec,
                                               MailServSpec,
                                               MaildropServSpec,
                                               SmtpProxyServSpec,
                                               Pop3ProxyServSpec]}};
        false ->
            {ok, {#{strategy => one_for_all}, []}}
    end.
