# A player

Players roam epidemic networks and as soon as a player encounters
another neighbour player they exchange re-encrypted messages from their
buffers according to the theories introduced by Golle and Spiridon et
al.

A player listens on SMTP and POP3 traffic in order to service
end-users with mail service on the epedemic network.

A player's characteristics can be configured using a players
configuration directive Obscrete's configuration files as seen in
./obscrete/etc/*.conf. It is possible to start many players on a
single Erlang node from a single configuration file but this is only
meaningfull in debug situations, i.e. during simulations etc.

## Files

<dl>
  <dt>./src/player_app.erl</dt>
  <dd>Top-level application module</dd>
  <dt>./src/player_sup.erl</dt>
  <dd>Top-level supervisor module</dd>
  <dt>./src/player_serv.erl</dt>
  <dd>A server which together with ./src/player_sync_serv.erl forms the core part of the Spridon message exchange algorithm</dd>
  <dt>./src/player_sync_serv.erl</dt>
  <dd>A server which does the actual exchange of messages between players</dd>
  <dt>./src/pop3_proxy_serv.erl</dt>
  <dd>A POP3 server which uses the epedemic nework as transport
  mechanism. It relies on functionality in the mail application.</dd>
  <dt>./src/smtp_proxy_serv.erl</dt>
  <dd>An SMTP server which uses the epedemic nework as transport mechanism. It relies on functionality in the mail application.</dd>
  <dt>./src/player_buffer.erl</dt>
  <dd>A buffer in which the player stores encrypted messages it receive from other players. It is not persistent as of today. It should be.</dd>
  <dt>./src/player_config_schema.erl</dt>
  <dd>Player/s has/have its/their own section/s in the Obscrete config file, e.g. see ./obscrete/etc/*.conf. This schema is activated in Obscrete's application file as seen in ./obscrete/ebin/obscrete.app.</dd>
  <dt>./src/player_db.erl</dt>
  <dd>SIMULATION: An API towards a public table which players use to store information which in turn is used by the simulator application</dd>
  <dt>./src/mail_serv.erl</dt>
  <dd>DEBUG: A server which can be used to send test emails/dd>
</dl>

## Unit testing

None
