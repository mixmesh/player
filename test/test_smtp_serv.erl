-module(test_smtp_serv).
-export([start/0]).

%% NOTE: swaks must be installed to run this test

start() ->
    true = is_substring(
             os:cmd("swaks --from alice@obscrete.net --to alice@obscrete.net --server 127.0.0.1:19900 --auth LOGIN --auth-user alice --tls-on-connect --auth-password baz --body \"FOO IS NOT BAR\""),
          "FOO IS NOT BAR").

is_substring(String, SubString) ->
    nomatch /= string:find(String, SubString).
