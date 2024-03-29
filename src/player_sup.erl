-module(player_sup).
-behaviour(supervisor).
-export([start_link/0, start_link/1]).
-export([init/1]). %% Used by supervisor:start_link/2

-include("../include/player_serv.hrl").

%%
%% Exported: start_link
%%

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

%%
%% Exported: init
%%

init(normal) ->
    Simulated = false,
    [MixmeshDir, PinSalt] =
        config:lookup_children(['mixmesh-dir', 'pin-salt'],
                               config:lookup([system])),
    [Nym, Routing, SyncServer, SmtpServer, Pop3Server, HttpServer] =
        config:lookup_children(
          [nym, routing, 'sync-server', 'smtp-server', 'pop3-server',
           'http-server'], config:lookup([player])),
    [RoutingType, UseGps, Longitude, Latitude] =
        config:lookup_children([type, 'use-gps', longitude, latitude], Routing),
    [SyncAddress, BufferSize, F, K, EncodedPublicKey, EncryptedSecretKey] =
        config:lookup_children([address, 'buffer-size', f, k, 'public-key',
                                'secret-key'],
                               SyncServer),
    Pk = elgamal:binary_to_pk(EncodedPublicKey),
    PinFilename = filename:join([MixmeshDir, <<"pin">>]),
    {ok, Pin} = file:read_file(PinFilename),
    SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
    {ok, DecryptedSecretKey} =
        player_crypto:shared_decrypt(SharedKey, EncryptedSecretKey),
    Sk = elgamal:binary_to_sk(DecryptedSecretKey),
    Keys = {Pk, Sk},
    [SmtpAddress, SmtpPasswordDigest] =
        config:lookup_children([address, 'password-digest'], SmtpServer),
    [Pop3Address, Pop3PasswordDigest] =
        config:lookup_children([address, 'password-digest'], Pop3Server),
    [HttpAddress, HttpPassword] =
        config:lookup_children([address, password], HttpServer),
    KeydirMode =
        case config:lookup([player, 'keydir-access-settings', mode]) of
            local ->
                local;
            service ->
                [Password, Address] =
                    config:lookup_children(
                      [password, address],
                      config:lookup(
                        [player, 'keydir-access-settings', service])),
                {service, Password, Address}
        end,
    PlayerDir = filename:join([MixmeshDir, Nym, <<"player">>]),
    TempDir = filename:join([PlayerDir, <<"temp">>]),
    BufferDir = filename:join([PlayerDir, <<"buffer">>]),
    SpoolerDir = filename:join([PlayerDir, <<"spooler">>]),
    LocalKeydirDir = filename:join([PlayerDir, <<"local-keydir">>]),
    CertFilename = filename:join([PlayerDir, <<"ssl">>, <<"cert.pem">>]),
    SharedDecodeKey = crypto:strong_rand_bytes(16),
    SessionDecodeKey = crypto:strong_rand_bytes(16),
    PlayerCryptoSpec =
	#{id => player_crypto_serv,
          start => {player_crypto_serv, start_link,
		    [PinSalt, EncryptedSecretKey,
		     SharedDecodeKey, SessionDecodeKey]}},
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Nym, SyncAddress, BufferSize, F, K, TempDir, BufferDir,
                     RoutingType, UseGps, Longitude, Latitude, Keys, not_set,
                     KeydirMode, Simulated]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Nym, SyncAddress, F, Keys, Simulated]}},
    HabitatServSpec =
        #{id => habitat_serv,
          start => {habitat_serv, start_link,
                    [Nym, Simulated]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, Simulated]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Nym, SmtpPasswordDigest, TempDir, CertFilename,
                     SmtpAddress, Simulated]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Nym, Pop3PasswordDigest, TempDir, CertFilename,
                     Pop3Address]}},
    RestServerSpecs =
        lists:map(fun({IpAddress, Port}) ->
                          #{id => {player_normal_service, {IpAddress, Port}},
                            start => {player_normal_service, start_link,
                                      [Nym, HttpPassword, TempDir, CertFilename,
                                       {IpAddress, Port}]}}
                  end, HttpAddress),
    LocalKeydirServSpec =
        #{id => keydir_serv,
          start => {local_keydir_serv, start_link, [LocalKeydirDir]}},
    {ok, {#{strategy => one_for_all},
          [PlayerCryptoSpec,
	   PlayerServSpec,
           PlayerSyncServSpec,
           HabitatServSpec,
           MaildropServSpec,
           SmtpServSpec,
           Pop3ServSpec] ++ RestServerSpecs ++
              [LocalKeydirServSpec]}};
init(#simulated_player_serv_config{
        players_dir = PlayersDir,
        nym = Nym,
        routing_type = RoutingType,
        use_gps = UseGps,
        longitude = Longitude,
        latitude = Latitude,
        sync_address = SyncAddress,
        buffer_size = BufferSize,
        f = F,
        k = K,
        keys = Keys,
        get_location_generator = GetLocationGenerator,
        smtp_address = SmtpAddress,
        smtp_password_digest = SmtpPasswordDigest,
        pop3_address = Pop3Address,
        pop3_password_digest = Pop3PasswordDigest,
        http_address = HttpAddress,
        http_password = HttpPassword,
        keydir_mode = KeydirMode}) ->
    Simulated = true,
    PlayerDir = filename:join([PlayersDir, Nym, <<"player">>]),
    TempDir = filename:join([PlayerDir, <<"temp">>]),
    BufferDir = filename:join([PlayerDir, <<"buffer">>]),
    SpoolerDir = filename:join([PlayerDir, <<"spooler">>]),
    LocalKeydirDir = filename:join([PlayerDir, <<"local-keydir">>]),
    CertFilename = filename:join([PlayerDir, <<"ssl">>, <<"cert.pem">>]),
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Nym, SyncAddress, BufferSize, F, K, TempDir, BufferDir,
                     RoutingType, UseGps, Longitude, Latitude, Keys,
                     GetLocationGenerator, KeydirMode, Simulated]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Nym, SyncAddress, F, Keys, Simulated]}},
    HabitatServSpec =
        #{id => habitat_serv,
          start => {habitat_serv, start_link,
                    [Nym, Simulated]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, Simulated]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Nym, SmtpPasswordDigest, TempDir, CertFilename,
                     SmtpAddress, Simulated]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Nym, Pop3PasswordDigest, TempDir, CertFilename,
                     Pop3Address]}},
    RestServerSpecs =
        lists:map(fun({IpAddress, Port}) ->
                          #{id => {player_normal_service, {IpAddress, Port}},
                            start => {player_normal_service, start_link,
                                      [Nym, HttpPassword, TempDir, CertFilename,
                                       {IpAddress, Port}]}}
                  end, HttpAddress),
    {_SyncIp, SyncPort} = SyncAddress,
    NodisServSpec =
        #{id => nodis_serv,
          start => {nodis_serv, start_link,
                    [#{simulation => Simulated,
		       mport => SyncPort,
		       oport => SyncPort + 1}]}},
    LocalKeydirServSpec =
        #{id => keydir_serv,
          start => {local_keydir_serv, start_link,
                    [LocalKeydirDir]}},
    {ok, {#{strategy => one_for_all},
          [PlayerServSpec,
           PlayerSyncServSpec,
           HabitatServSpec,
           MaildropServSpec,
           SmtpServSpec,
           Pop3ServSpec] ++ RestServerSpecs ++
              [NodisServSpec,
               LocalKeydirServSpec]}}.
