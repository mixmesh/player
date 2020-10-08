-module(player_sup).
-behaviour(supervisor).
-export([start_link/0, start_link/15]).
-export([attach_child/3]).
-export([init/1]).

%% Exported: start_link

start_link() ->
    start_link([]).

%% NOTE: Used by the simulator
start_link(Name, Password, SyncIpAddress, SyncPort, TempDir, Keys, F,
           GetLocationGenerator, DegreesToMeter, SmtpIpAddress, SmtpPort,
           SpoolerDir, Pop3IpAddress, Pop3Port, PkiDataDir) ->
    start_link([Name, Password, SyncIpAddress, SyncPort, TempDir, Keys, F,
                GetLocationGenerator, DegreesToMeter, SmtpIpAddress, SmtpPort,
                SpoolerDir, Pop3IpAddress, Pop3Port, PkiDataDir]).

start_link(Args) ->
    case supervisor:start_link(?MODULE, Args) of
        {ok, Pid} ->
            Children = supervisor:which_children(Pid),
            ok = attach_child(player_serv,
                              [mail_serv, maildrop_serv, nodis_serv],
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
    [Name, Password, {SyncIpAddress, SyncPort}, TempDir, Spiridon, Maildrop,
     SmtpProxy, Pop3Proxy] =
        config:lookup_children(
          [username, password, 'sync-address', 'temp-dir', spiridon, maildrop,
           'smtp-proxy', 'pop3-proxy'],
          config:lookup([player])),
    [F, PublicKey, SecretKey] =
        config:lookup_children([f, 'public-key', 'secret-key'], Spiridon),
    Keys = {PublicKey, SecretKey},
    [SpoolerDir] = config:lookup_children(['spooler-dir'], Maildrop),
    [{SmtpIpAddress, SmtpPort}] = config:lookup_children([address], SmtpProxy),
    [{Pop3IpAddress, Pop3Port}] = config:lookup_children([address], Pop3Proxy),
    PkiDataDir = config:lookup([player, pki, 'data-dir']),
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Name, Password, SyncIpAddress, SyncPort, TempDir,
                     {PublicKey, SecretKey}, not_set, not_set, false]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Name, SyncIpAddress, SyncPort, F, Keys]}},
    MailServSpec =
        #{id => mail_serv,
          start => {mail_serv, start_link, [Name, SmtpIpAddress, SmtpPort]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, false]}},
    SmtpProxyServSpec =
        #{id => smtp_proxy_serv,
          start => {smtp_proxy_serv, start_link,
                    [Name, Password, TempDir, SmtpIpAddress, SmtpPort, false]}},
    Pop3ProxyServSpec =
        #{id => pop3_proxy_serv,
          start => {pop3_proxy_serv, start_link,
                    [Name, Password, TempDir, Pop3IpAddress, Pop3Port]}},
    NodisServSpec =
        #{id => nodis_serv,
          start => {nodis_srv, start_link_sim, []}},
    PkiServSpec =
        #{id => pki_serv,
          start => {pki_serv, start_link, [none, PkiDataDir]}},
    {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                       PlayerSyncServSpec,
                                       MailServSpec,
                                       MaildropServSpec,
                                       SmtpProxyServSpec,
                                       Pop3ProxyServSpec,
                                       NodisServSpec,
                                       PkiServSpec]}};
init([Name, Password, SyncIpAddress, SyncPort, TempDir, Keys, F,
      GetLocationGenerator, DegreesToMeter, SmtpIpAddress, SmtpPort,
      SpoolerDir, Pop3IpAddress, Pop3Port, PkiDataDir]) ->
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Name, Password, SyncIpAddress, SyncPort, TempDir,
                     Keys, GetLocationGenerator, DegreesToMeter, true]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Name, SyncIpAddress, SyncPort, F, Keys]}},
    MailServSpec =
        #{id => mail_serv,
          start => {mail_serv, start_link,
                    [Name, SmtpIpAddress, SmtpPort]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link,
                    [SpoolerDir, true]}},
    SmtpProxyServSpec =
        #{id => smtp_proxy_serv,
          start => {smtp_proxy_serv, start_link,
                    [Name, Password, TempDir, SmtpIpAddress, SmtpPort, true]}},
    Pop3ProxyServSpec =
        #{id => pop3_proxy_serv,
          start => {pop3_proxy_serv, start_link,
                    [Name, Password, TempDir, Pop3IpAddress, Pop3Port]}},
    NodisServSpec =
        #{id => nodis_serv,
          start => {nodis_srv, start_link_sim, []}},
    PkiServSpec =
        #{id => pki_serv,
          start => {pki_serv, start_link, [none, PkiDataDir]}},
    {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                       PlayerSyncServSpec,
                                       MailServSpec,
                                       MaildropServSpec,
                                       SmtpProxyServSpec,
                                       Pop3ProxyServSpec,
                                       NodisServSpec,
                                       PkiServSpec]}}.
