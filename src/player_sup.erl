-module(player_sup).
-behaviour(supervisor).
-export([start_link/0, start_link/13]).
-export([attach_child/3]).
-export([init/1]).

%% Exported: start_link

start_link() ->
    start_link([]).

start_link(Name, Password, SyncAddress, SyncPort, TempDir, F,
           GetLocationGenerator, DegreesToMeter, SmtpAddress, SmtpPort,
           SpoolerDir, Pop3Address, Pop3Port) ->
    start_link([Name, Password, SyncAddress, SyncPort, TempDir, F,
                GetLocationGenerator, DegreesToMeter, SmtpAddress, SmtpPort,
                SpoolerDir, Pop3Address, Pop3Port]).

start_link(Args) ->
    case supervisor:start_link(?MODULE, Args) of
        {ok, Pid} ->
            Children = supervisor:which_children(Pid),
            ok = attach_child(player_serv, [mail_serv, maildrop_serv],
                              Children),
            ok = attach_child(player_sync_serv, player_serv, Children),
            ok = attach_child(smtp_proxy_serv, player_serv, Children),
            ok = attach_child(pop3_proxy_serv, maildrop_serv, Children),
            {ok, Pid};
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
    [Name, Password, {SyncAddress, SyncPort}, TempDir, Spiridon, Maildrop,
     SmtpProxy, Pop3Proxy] =
        config:lookup_children(
          [username, password, 'sync-address', 'temp-dir', spiridon, maildrop,
           'smtp-proxy', 'pop3-proxy'],
          config:lookup([player])),
    [F] = config:lookup_children([f], Spiridon),
    [SpoolerDir] = config:lookup_children(['spooler-dir'], Maildrop),
    [{SmtpAddress, SmtpPort}] = config:lookup_children([address], SmtpProxy),
    [{Pop3Address, Pop3Port}] = config:lookup_children([address], Pop3Proxy),
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Name, SyncAddress, SyncPort, TempDir, not_set, not_set,
                     false]}},
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
          start => {maildrop_serv, start_link,
                    [SpoolerDir, false]}},
    SmtpProxyServSpec =
        #{id => smtp_proxy_serv,
          start => {smtp_proxy_serv, start_link,
                    [Name, Password, TempDir, SmtpAddress, SmtpPort, false]}},
    Pop3ProxyServSpec =
        #{id => pop3_proxy_serv,
          start => {pop3_proxy_serv, start_link,
                    [Name, Password, TempDir, Pop3Address, Pop3Port]}},
    {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                       PlayerSyncServSpec,
                                       MailServSpec,
                                       MaildropServSpec,
                                       SmtpProxyServSpec,
                                       Pop3ProxyServSpec]}};
init([Name, Password, SyncAddress, SyncPort, TempDir, F, GetLocationGenerator,
      DegreesToMeter, SmtpAddress, SmtpPort, SpoolerDir, Pop3Address,
      Pop3Port]) ->
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Name, SyncAddress, SyncPort, TempDir,
                     GetLocationGenerator, DegreesToMeter, true]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Name, SyncAddress, SyncPort, F, true]}},
    MailServSpec =
        #{id => mail_serv,
          start => {mail_serv, start_link,
                    [Name, SmtpAddress, SmtpPort]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link,
                    [SpoolerDir, true]}},
    SmtpProxyServSpec =
        #{id => smtp_proxy_serv,
          start => {smtp_proxy_serv, start_link,
                    [Name, Password, TempDir, SmtpAddress, SmtpPort, true]}},
    Pop3ProxyServSpec =
        #{id => pop3_proxy_serv,
          start => {pop3_proxy_serv, start_link,
                    [Name, Password, TempDir, Pop3Address, Pop3Port]}},
    {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                       PlayerSyncServSpec,
                                       MailServSpec,
                                       MaildropServSpec,
                                       SmtpProxyServSpec,
                                       Pop3ProxyServSpec]}}.
