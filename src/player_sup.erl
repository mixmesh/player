-module(player_sup).
-behaviour(supervisor).
-export([start_link/0, start_link/1]).
-export([init/1]). %% Used by supervisor:start_link/2

-include("../include/player_serv.hrl").

%% Exported: start_link

-spec start_link(normal | #simulated_player_serv_config{}) -> any().

start_link() ->
    start_link(normal).

start_link(Config) ->
    case supervisor:start_link(?MODULE, Config) of
        {ok, SupervisorPid} ->
            supervisor_helper:foreach_worker(
              SupervisorPid,
              fun(player_serv, Pid, NeighbourWorkers) when Config == normal ->
                      LessNeighbourWorkers =
                          lists:keydelete(nodis_serv, 1, NeighbourWorkers),
                      Pid ! {neighbour_workers, LessNeighbourWorkers};
                 (_Id, Pid, NeighbourWorkers) ->
                      Pid ! {neighbour_workers, NeighbourWorkers}
              end),
            {ok, SupervisorPid};
        Error ->
            Error
    end.

%% Exported: init

init(normal) ->
    [ObscreteDir, PinSalt] =
        config:lookup_children(['obscrete-dir', 'pin-salt'],
                               config:lookup([system])),
    [Nym, SyncAddress, Routing, SmtpServer, Pop3Server, HttpServer] =
        config:lookup_children(
          [nym, 'sync-address', routing, 'smtp-server', 'pop3-server',
           'http-server'], config:lookup([player])),
    [RoutingType, F, EncodedPublicKey, EncryptedSecretKey] =
        config:lookup_children([type, f, 'public-key', 'secret-key'], Routing),
    PublicKey = elgamal:binary_to_public_key(EncodedPublicKey),
    PinFilename = filename:join([ObscreteDir, <<"pin">>]),
    {ok, Pin} = file:read_file(PinFilename),
    SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
    {ok, DecryptedSecretKey} =
        player_crypto:shared_decrypt(SharedKey, EncryptedSecretKey),
    SecretKey = elgamal:binary_to_secret_key(DecryptedSecretKey),
    Keys = {PublicKey, SecretKey},
    [SmtpAddress, SmtpPasswordDigest] =
        config:lookup_children([address, 'password-digest'], SmtpServer),
    [Pop3Address, Pop3PasswordDigest] =
        config:lookup_children([address, 'password-digest'], Pop3Server),
    [HttpAddress, HttpPassword] =
        config:lookup_children([address, password], HttpServer),
    PkiMode =
        case config:lookup([player, 'pki-access-settings', mode]) of
            local ->
                local;
            global ->
                [PkiPassword, PkiAccess, PkiServerTorAddress,
                 PkiServerTcpAddress] =
                    config:lookup_children(
                      [password, access, 'pki-server-tor-address',
                       'pki-server-tcp-address'],
                      config:lookup([player, 'pki-access-settings', global])),
                case PkiAccess of
                    tor_only ->
                        {global, PkiPassword, {tor_only, PkiServerTorAddress}};
                    tcp_only ->
                        {global, PkiPassword, {tcp_only, PkiServerTcpAddress}};
                    tor_fallback_to_tcp ->
                        {global, PkiPassword,
                         {tor_fallback_to_tcp, PkiServerTorAddress,
                          PkiServerTcpAddress}}
                end
        end,
    PlayerDir = filename:join([ObscreteDir, Nym, <<"player">>]),
    TempDir = filename:join([PlayerDir, <<"temp">>]),
    BufferDir = filename:join([PlayerDir, <<"buffer">>]),
    SpoolerDir = filename:join([PlayerDir, <<"spooler">>]),
    LocalPkiDir = filename:join([PlayerDir, <<"local-pki">>]),
    CertFilename = filename:join([PlayerDir, <<"ssl">>, <<"cert.pem">>]),
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Nym, SyncAddress, TempDir, BufferDir, RoutingType, Keys,
                     not_set, not_set, PkiMode, _Simulated = false]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Nym, SyncAddress, F, Keys, _Simulated = false]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, false]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Nym, SmtpPasswordDigest, TempDir, CertFilename,
                     SmtpAddress, _Simulated = false]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Nym, Pop3PasswordDigest, TempDir, CertFilename,
                     Pop3Address]}},
    RestServerSpecs =
        lists:map(fun({IpAddress, Port}) ->
                          #{id => {rest_normal_server, {IpAddress, Port}},
                            start => {rest_normal_server, start_link,
                                      [Nym, HttpPassword, TempDir, CertFilename,
                                       {IpAddress, Port}]}}
                  end, HttpAddress),
    LocalPkiServSpec =
        #{id => pki_serv,
          start => {local_pki_serv, start_link, [LocalPkiDir]}},
    {ok, {#{strategy => one_for_all},
          [PlayerServSpec,
           PlayerSyncServSpec,
           MaildropServSpec,
           SmtpServSpec,
           Pop3ServSpec] ++ RestServerSpecs ++
              [LocalPkiServSpec]}};
init(#simulated_player_serv_config{
        players_dir = PlayersDir,
        nym = Nym,
        sync_address = SyncAddress,
        routing_type = RoutingType,
        keys = Keys,
        f = F,
        get_location_generator = GetLocationGenerator,
        degrees_to_meters = DegreesToMeters,
        smtp_address = SmtpAddress,
        smtp_password_digest = SmtpPasswordDigest,
        pop3_address = Pop3Address,
        pop3_password_digest = Pop3PasswordDigest,
        http_address = HttpAddress,
        http_password = HttpPassword,
        pki_mode = PkiMode}) ->
    PlayerDir = filename:join([PlayersDir, Nym, <<"player">>]),
    TempDir = filename:join([PlayerDir, <<"temp">>]),
    BufferDir = filename:join([PlayerDir, <<"buffer">>]),
    SpoolerDir = filename:join([PlayerDir, <<"spooler">>]),
    LocalPkiDir = filename:join([PlayerDir, <<"local-pki">>]),
    CertFilename = filename:join([PlayerDir, <<"ssl">>, <<"cert.pem">>]),
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Nym, SyncAddress, TempDir, BufferDir, RoutingType, Keys,
                     GetLocationGenerator, DegreesToMeters, PkiMode, true]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Nym, SyncAddress, F, Keys, _Simulated=true]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, true]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Nym, SmtpPasswordDigest, TempDir, CertFilename,
                     SmtpAddress, true]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Nym, Pop3PasswordDigest, TempDir, CertFilename,
                     Pop3Address]}},
    RestServerSpecs =
        lists:map(fun({IpAddress, Port}) ->
                          #{id => {rest_normal_server, {IpAddress, Port}},
                            start => {rest_normal_server, start_link,
                                      [Nym, HttpPassword, TempDir, CertFilename,
                                       {IpAddress, Port}]}}
                  end, HttpAddress),
    {_SyncIp, SyncPort} = SyncAddress,
    NodisServSpec =
        #{id => nodis_serv,
          start => {nodis_serv, start_link,
                    [#{simulation => true,
		       mport => SyncPort,
		       oport => SyncPort + 1}]}},
    LocalPkiServSpec =
        #{id => pki_serv,
          start => {local_pki_serv, start_link,
                    [LocalPkiDir]}},
    {ok, {#{strategy => one_for_all},
          [PlayerServSpec,
           PlayerSyncServSpec,
           MaildropServSpec,
           SmtpServSpec,
           Pop3ServSpec] ++ RestServerSpecs ++
              [NodisServSpec,
               LocalPkiServSpec]}}.
