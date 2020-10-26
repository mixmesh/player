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
    [Pin, PinSalt] =
        config:lookup_children([pin, 'pin-salt'], config:lookup([system])),
    [Nym, PkiPassword, SyncAddress, TempDir, BufferDir, Spiridon,
     Maildrop, SmtpServer, Pop3Server, HttpServer] =
        config:lookup_children(
          [nym, 'pki-password', 'sync-address', 'temp-dir', 'buffer-dir',
           spiridon, maildrop, 'smtp-server', 'pop3-server', 'http-server'],
          config:lookup([player])),
    [F, EncodedPublicKey, EncryptedSecretKey] =
        config:lookup_children([f, 'public-key', 'secret-key'], Spiridon),
    PublicKey = elgamal:binary_to_public_key(EncodedPublicKey),
    SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
    {ok, DecryptedSecretKey} =
        player_crypto:decrypt_secret_key(SharedKey, EncryptedSecretKey),
    SecretKey = elgamal:binary_to_secret_key(DecryptedSecretKey),
    Keys = {PublicKey, SecretKey},
    [SpoolerDir] = config:lookup_children(['spooler-dir'], Maildrop),
    [SmtpAddress, SmtpCertFilename, SmtpPasswordDigest] =
        config:lookup_children([address, 'cert-filename', 'password-digest'],
                               SmtpServer),
    [Pop3Address, Pop3CertFilename, Pop3PasswordDigest] =
        config:lookup_children([address, 'cert-filename', 'password-digest'],
                               Pop3Server),
    [HttpAddress, HttpCertFilename, HttpPassword] =
        config:lookup_children([address, 'cert-filename', password],
                               HttpServer),
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
                    [Nym, PkiPassword, SyncAddress, TempDir, BufferDir, Keys,
                     not_set, not_set, PkiMode, false]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Nym, SyncAddress, F, Keys, _Simulated=false]}},
    MailServSpec =
        #{id => mail_serv,
          start => {mail_serv, start_link, [Nym, SmtpAddress]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, false]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Nym, SmtpPasswordDigest, TempDir, SmtpCertFilename,
                     SmtpAddress, false]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Nym, Pop3PasswordDigest, TempDir, Pop3CertFilename,
                     Pop3Address]}},
    RestServerSpec =
	#{id => rest_server,
          start => {rest_server, start_link,
                    [Nym, HttpPassword, HttpCertFilename, HttpAddress]}},
%% now always start one nodis_serv (but may be a dummy if sumulation)
%%    NodisServSpec =
%%        #{id => nodis_serv,
%%          start => {nodis_serv, start_link, [#{}]}},
    LocalPkiServSpec =
        #{id => pki_serv,
          start => {pki_serv, start_link, [local, LocalPkiServerDataDir]}},
    {ok, {#{strategy => one_for_all}, [PlayerServSpec,
                                       PlayerSyncServSpec,
                                       MailServSpec,
                                       MaildropServSpec,
                                       SmtpServSpec,
                                       Pop3ServSpec,
                                       RestServerSpec,
                                       %% NodisServSpec,
                                       LocalPkiServSpec]}};
init(#simulated_player_serv_config{
        nym = Nym,
        pki_password = PkiPassword,
        sync_address = SyncAddress,
        temp_dir = TempDir,
        buffer_dir = BufferDir,
        keys = Keys,
        f = F,
        get_location_generator = GetLocationGenerator,
        degrees_to_meters = DegreesToMeters,
        spooler_dir = SpoolerDir,
        smtp_address = SmtpAddress,
        smtp_cert_filename = SmtpCertFilename,
        smtp_password_digest = SmtpPasswordDigest,
        pop3_address = Pop3Address,
        pop3_cert_filename = Pop3CertFilename,
        pop3_password_digest = Pop3PasswordDigest,
        http_address = HttpAddress,
        http_cert_filename = HttpCertFilename,
        http_password = HttpPassword,
        local_pki_server_data_dir = LocalPkiServerDataDir,
        pki_mode = PkiMode}) ->
    PlayerServSpec =
        #{id => player_serv,
          start => {player_serv, start_link,
                    [Nym, PkiPassword, SyncAddress, TempDir, BufferDir, Keys,
                     GetLocationGenerator, DegreesToMeters, PkiMode, true]}},
    PlayerSyncServSpec =
        #{id => player_sync_serv,
          start => {player_sync_serv, start_link,
                    [Nym, SyncAddress, F, Keys, _Simulated=true]}},
    MailServSpec =
        #{id => mail_serv,
          start => {mail_serv, start_link, [Nym, SmtpAddress]}},
    MaildropServSpec =
        #{id => maildrop_serv,
          start => {maildrop_serv, start_link, [SpoolerDir, true]}},
    SmtpServSpec =
        #{id => smtp_serv,
          start => {smtp_serv, start_link,
                    [Nym, SmtpPasswordDigest, TempDir, SmtpCertFilename,
                     SmtpAddress, true]}},
    Pop3ServSpec =
        #{id => pop3_serv,
          start => {pop3_serv, start_link,
                    [Nym, Pop3PasswordDigest, TempDir, Pop3CertFilename,
                     Pop3Address]}},
    RestServerSpec =
	#{id => rest_server,
          start => {rest_server, start_link,
                    [Nym, HttpPassword, HttpCertFilename, HttpAddress]}},
    NodisServSpec =
        #{id => nodis_serv,
          start => {nodis_serv, start_link,
                    [#{simulation => true,
                       'ping-interval' => 500,
                       'max-ping-lost' => 2}]}},
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
                                       RestServerSpec,
                                       NodisServSpec,
                                       LocalPkiServSpec]}}.
