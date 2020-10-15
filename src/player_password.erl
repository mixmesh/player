-module(player_password).
-export([salt/1, check/2]).

-include_lib("apptools/include/shorthand.hrl").

%% Exported: salt

-spec salt(binary()) -> binary().

salt(Password) ->
    Salt = crypto:strong_rand_bytes(32),
    SaltedDigest = crypto:hash(sha256, [Salt, Password]),
    base64:encode(?l2b([Salt, SaltedDigest])).

%% Exported: check

-spec check(binary(), binary()) -> boolean().

check(Password, PasswordDigest) ->
    <<Salt:32/binary, SaltedDigest/binary>> = base64:decode(PasswordDigest),
    crypto:hash(sha256, [Salt, Password]) == SaltedDigest.
