-module(player_sup).
-behaviour(supervisor).
-export([start_link/0, start_link/13]).
-export([attach_child/3]).
-export([init/1]).

%% Exported: start_link

start_link() ->
    start_link([]).

start_link(Args) ->
    case supervisor:start_link(?MODULE, Args) of
        {ok, Pid} ->
            Children = supervisor:which_children(Pid),
            ok = attach_child(player_serv,
                              [mail_serv, maildrop_serv, nodis_serv, pki_serv],
                              Children),
            ok = attach_child(player_sync_serv, player_serv, Children),
            ok = attach_child(smtp_serv, player_serv, Children),
            ok = attach_child(pop3_serv, maildrop_serv, Children),
            {ok, Pid};
        Error ->
            Error
    end.

%% NOTE: Used by simulator_serv.erl
start_link(Name, Password, SyncAddress, TempDir, Keys, F, GetLocationGenerator,
           DegreesToMeter, SmtpAddress, SpoolerDir, Pop3Address,
           LocalPkiServerDataDir, PkiMode) ->
    start_link([Name, Password, SyncAddress, TempDir, Keys, F,
                GetLocationGenerator, DegreesToMeter, SmtpAddress, SpoolerDir,
                Pop3Address, LocalPkiServerDataDir, PkiMode]).

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
    [Name, Password, SyncAddress, TempDir, Spiridon, Maildrop, SmtpServer,
     Pop3Server] =
        config:lookup_children(
          [username, password, 'sync-address', 'temp-dir', spiridon, maildrop,
           'smtp-server', 'pop3-server'],
          config:lookup([player])),
    [F, PublicKey, SecretKey] =
        config:lookup_children([f, 'public-key', 'secret-key'], Spiridon),
    Keys = {PublicKey, SecretKey},
    [SpoolerDir] = config:lookup_children(['spooler-dir'], Maildrop),
    [SmtpAddress] = config:lookup_children([address], SmtpServer),
    [Pop3Address] = config:lookup_children([address], Pop3Server),
    LocalPkiServerDataDir =
        config:lookup([player, 'local-pki-server', 'data-dir']),
    PkiMode =
        case config:lookup([player, 'pki-access-settings', mode]) of
            local ->
                local;
            global ->
                [PkiAccess, PkiServerTorAddress, PkiServerTcpAddress] =
                    config:lookup_children(
                      [access,
                       'pki-server-tor-address',
                       'pki-server-tcp-address'],
                      config:lookup([player, 'pki-access-settings', global])),
                case PkiAccess of
                    tor_only ->
                        {global, {tor_only, PkiServerTorAddress}};
                    tcp_only ->
                        {global, {tcp_only, PkiServerTcpAddress}};
                    tor_fallback_to_tcp ->
                        {global, {tor_fallback_to_tcp,
                                  PkiServerTorAddress, PkiServerTcpAddress}}
                end
        end,
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Name, Password, SyncAddress, TempDir, Keys, not_set,
                     not_set, PkiMode, false]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Name, SyncAddress, F, Keys]}},
    MailServSpec =
        #{id => mail_serv,
          start => {mail_serv, start_link, [Name, SmtpAddress]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, false]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Name, Password, TempDir, SmtpAddress, false]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Name, Password, TempDir, Pop3Address]}},
    NodisServSpec =
        #{id => nodis_serv,
          start => {nodis_srv, start_link_sim,
                    [#{simulation => true,
                       ping_interval => 500,
                       max_ping_lost => 2}]}},
    LocalPkiServSpec =
        #{id => pki_serv,
          start => {pki_serv, start_link, [local, LocalPkiServerDataDir]}},
    {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                       PlayerSyncServSpec,
                                       MailServSpec,
                                       MaildropServSpec,
                                       SmtpServSpec,
                                       Pop3ServSpec,
                                       NodisServSpec,
                                       LocalPkiServSpec]}};
init([Name, Password, SyncAddress, TempDir, Keys, F, GetLocationGenerator,
      DegreesToMeter, SmtpAddress, SpoolerDir, Pop3Address,
      LocalPkiServerDataDir, PkiMode]) ->
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Name, Password, SyncAddress, TempDir, Keys,
                     GetLocationGenerator, DegreesToMeter, PkiMode, true]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Name, SyncAddress, F, Keys]}},
    MailServSpec =
        #{id => mail_serv,
          start => {mail_serv, start_link, [Name, SmtpAddress]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, true]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Name, Password, TempDir, SmtpAddress, true]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Name, Password, TempDir, Pop3Address]}},
    NodisServSpec =
        #{id => nodis_serv,
          start => {nodis_srv, start_link_sim,
                    [#{simulation => true,
                       ping_interval => 500,
                       max_ping_lost => 2}]}},
    LocalPkiServSpec =
        #{id => pki_serv,
          start => {pki_serv, start_link,
                    [local, LocalPkiServerDataDir]}},
    {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                       PlayerSyncServSpec,
                                       MailServSpec,
                                       MaildropServSpec,
                                       SmtpServSpec,
                                       Pop3ServSpec,
                                       NodisServSpec,
                                       LocalPkiServSpec]}}.
