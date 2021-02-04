# A player

Players roam epedemic networks and as soon as a player encounters
another neighbour player they exchange re-encrypted messages from their
message buffers according to the theories introduced by Golle and
Spiridon et al.

A player listens on incoming SMTP and POP3 traffic in order to service
end-users with mail access on the epedemic network.

A player's characteristics can be configured using a players
configuration directive in Mixmesh's configuration files as seen in
./mixmesh/etc/*.conf.

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
  <dd>Player/s has/have its/their own section/s in the Mixmesh config file, e.g. see ./mixmesh/etc/*.conf. This schema is activated in Mixmesh's application file as seen in ./mixmesh/ebin/mixmesh.app.</dd>
  <dt>./test/test_pop3_serv.erl</dt>
  <dd>Test for the pop3_serv module</dd>
  <dt>./test/test_smtp_serv.erl</dt>
  <dd>Test for the smtp_serv module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

`$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh.conf test/`

Tests can be run individually as well:

```
$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh.conf pop3_serv
$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh.conf smtp_serv
```
