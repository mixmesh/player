-module(test_pop3_serv).
-export([start/0]).

%% NOTE: mpop must be installed to run this test

start() ->
    Filename = mail_util:mktemp(<<"/tmp">>),
    ok = file:write_file(Filename, <<"FOO\r\n">>),
    ok = write_to_maildrop(Filename, 5),
    ok = file:delete(Filename),
    true =
        is_substring(
          os:cmd("mpop --host=127.0.0.1 --port=29900 --serverinfo"),
          "POP3 server ready"),
    os:cmd("rm -fr $HOME/.mpop_uidls alice"),
    true =
        is_substring(os:cmd("mpop --host=127.0.0.1 --port=29900 --deliver=mbox,alice --keep=on --auth=user --user=alice --passwordeval='echo \"baz\"'"),
                     "retrieving message 5").

write_to_maildrop(_Filename, 0) ->
    ok;
write_to_maildrop(Filename, N) ->
    {ok, _} = maildrop_serv:write(maildrop_serv, Filename),
    write_to_maildrop(Filename, N - 1).

is_substring(String, SubString) ->
    nomatch /= string:find(String, SubString).
