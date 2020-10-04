# A player

Players roam epedemic networks and as soon as a player encounters
another neighbour player they exchange re-encrypted messages from their
buffers according to the theories introduced by Golle and Spiridon et
al.

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
  <dd>Top-level application module</dd>
  <dt>./src/player_sup.erl</dt>
  <dd>Top-level supervisor module</dd>
  <dt>./src/player_serv.erl</dt>
  <dd>A server which together with ./src/player_sync_serv.erl forms the core part of the Spridon message exchange algorithm</dd>
  <dt>./src/player_sync_serv.erl</dt>
  <dd>A server which does the actual exchange of messages between players</dd>
  <dt>./src/pop3_proxy_serv.erl</dt>
  <dd>A POP3 server which uses the epedemic network as transport
  mechanism. It relies on functionality in the mail application.</dd>
  <dt>./src/smtp_proxy_serv.erl</dt>
  <dd>An SMTP server which uses the epedemic network as transport mechanism. It relies on functionality in the mail application.</dd>
  <dt>./src/player_buffer.erl</dt>
  <dd>A buffer in which the player stores encrypted messages it receives from other players. It is not persistent as of today. It should be.</dd>
  <dt>./src/player_config_schema.erl</dt>
  <dd>Player/s has/have its/their own section/s in the Obscrete config file, e.g. see ./obscrete/etc/*.conf. This schema is activated in Obscrete's application file as seen in ./obscrete/ebin/obscrete.app.</dd>
  <dt>./test/test_pop3_proxy_serv.erl</dt>
  <dd>Test for the pop3_proxy_serv module</dd>
  <dt>./test/test_smtp_proxy_serv.erl</dt>
  <dd>Test for the smtp_proxy_serv module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

`$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete.conf test/`

Tests can be run individually as well:

```
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete.conf pop3_proxy_serv
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete.conf smtp_proxy_serv
```
