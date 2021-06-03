-module(player_crypto).
-export([digest_password/1, check_digested_password/2]).
-export([make_key_pair/3]).
-export([generate_shared_key/2, shared_encrypt/2, shared_decrypt/2]).
-export([pin_salt/0, pin_to_shared_key/2]).

-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").

%%
%% Exported: digest_password
%%

-spec digest_password(binary()) -> binary().

digest_password(Password) ->
    Salt = crypto:strong_rand_bytes(32),
    DigestPassword = crypto:hash(sha256, [Salt, Password]),
    ?l2b([Salt, DigestPassword]).

%%
%% Exported: check_digested_password
%%

-spec check_digested_password(binary(), binary()) -> boolean().

check_digested_password(Password, <<Salt:32/binary, DigestPassword/binary>>) ->
    crypto:hash(sha256, [Salt, Password]) == DigestPassword.

%%
%% Exported: make_key_pair
%%

-spec make_key_pair(string(), binary(), string()) ->
          {ok, binary(), binary(), binary()} | {error, string()}.

make_key_pair(Pin, PinSalt, Nym) ->
    case {length(Pin), lists:all(fun(C) -> C >= $0 andalso C =< $9 end, Pin)} of
        _ when length(Nym) > ?MAX_NYM_SIZE ->
            {error, io_lib:format("A nym must at most contain ~w characters",
                                  [(?MAX_NYM_SIZE)])};
        {PinLen, _} when PinLen /= 6 ->
            {error, "A pin must contain six digits"};
        {_PinLen, false} ->
            {error, "A pin must only contain digits"};
        _ ->
            SharedKey =
                enacl:pwhash(?l2b(Pin), PinSalt, enacl:secretbox_KEYBYTES()),
            {PublicKey, SecretKey} = elgamal:generate_key_pair(?l2b(Nym)),
            PublicKeyBin = elgamal:public_key_to_binary(PublicKey),
            SecretKeyBin = elgamal:secret_key_to_binary(SecretKey),
            Nonce = enacl:randombytes(enacl:secretbox_NONCEBYTES()),
            EncryptedSecretKey = enacl:secretbox(SecretKeyBin, Nonce, SharedKey),
            {ok, PublicKeyBin, SecretKeyBin, <<Nonce/binary, EncryptedSecretKey/binary>>}
    end.

%%
%% Exported: generate_shared_key
%%

-spec generate_shared_key(binary(), binary()) -> binary().

generate_shared_key(Pin, PinSalt) ->
    enacl:pwhash(Pin, PinSalt, enacl:secretbox_KEYBYTES()).

%%
%% Exported: shared_encrypt
%%

-spec shared_encrypt(binary(), binary()) -> {ok, binary()}.

shared_encrypt(SharedKey, Plaintext) ->
    Nonce = enacl:randombytes(enacl:secretbox_NONCEBYTES()),
    Ciphertext = enacl:secretbox(Plaintext, Nonce, SharedKey),
    {ok, <<Nonce/binary, Ciphertext/binary>>}.

%%
%% Exported: shared_decrypt
%%

-spec shared_decrypt(binary(), binary()) ->
          {ok, binary()} | {error, failed_verification}.

shared_decrypt(SharedKey, NonceAndCiphertext) ->
    NonceSize = enacl:secretbox_NONCEBYTES(),
    <<Nonce:NonceSize/binary, Ciphertext/binary>> =
        NonceAndCiphertext,
    enacl:secretbox_open(Ciphertext, Nonce, SharedKey).

%%
%% Exported: pin_salt
%%

-spec pin_salt() -> binary().

pin_salt() ->
    enacl:randombytes(enacl:pwhash_SALTBYTES()).

%%
%% Exported: pin_to_shared_key
%%

-spec pin_to_shared_key(binary(), binary()) -> binary().

pin_to_shared_key(Pin, Salt) ->
    enacl:pwhash(Pin, Salt, enacl:secretbox_KEYBYTES()).
