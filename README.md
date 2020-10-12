# A player

Players roam epedemic networks and as soon as a player encounters
another neighbour player they exchange re-encrypted messages from their
message buffers according to the theories introduced by Golle and
Spiridon et al.

A player listens on incoming SMTP and POP3 traffic in order to service
end-users with mail access on the epedemic network.

A player's characteristics can be configured using a players
configuration directive in Obscrete's configuration files as seen in
./obscrete/etc/*.conf.

It is possible to start many players on a single Erlang node,
i.e. you start several player_sup supervisors. This is what the
simulator application does.

## Files

<dl>
  <dt>./src/player_app.erl</dt>
  <dd>The top-level application module</dd>
  <dt>./src/player_sup.erl</dt>
  <dd>The top-level supervisor module</dd>
  <dt>./src/player_serv.erl</dt>
  <dd>A player server which together with player_sync_serv.erl forms the core part of the Spridon message exchange algorithm</dd>
  <dt>./src/player_sync_serv.erl</dt>
  <dd>A server which does the actual exchange of messages between players</dd>
  <dt>./src/pop3_serv.erl</dt>
  <dd>A POP3 server which uses the epedemic network as transport
  mechanism. It relies on functionality in the mail repository.</dd>
  <dt>./src/smtp_serv.erl</dt>
  <dd>An SMTP server which uses the epedemic network as transport mechanism. It relies on functionality in the mail repository.</dd>
  <dt>./src/player_buffer.erl</dt>
  <dd>A message buffer in which the player stores encrypted messages it receives from other players (and from itself). It is not persistent as of today. It should be.</dd>
  <dt>./src/player_config_schema.erl</dt>
  <dd>Player/s has/have its/their own section/s in the Obscrete config file, e.g. see ./obscrete/etc/*.conf. This schema is activated in Obscrete's application file as seen in ./obscrete/ebin/obscrete.app.</dd>
  <dt>./test/test_pop3_serv.erl</dt>
  <dd>Test for the pop3_serv module</dd>
  <dt>./test/test_smtp_serv.erl</dt>
  <dd>Test for the smtp_serv module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

`$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete.conf test/`

Tests can be run individually as well:

```
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete.conf pop3_serv
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete.conf smtp_serv
```
