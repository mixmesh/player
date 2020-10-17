-module(player_crypto).
-export([digest_password/1, check_digested_password/2]).
-export([encrypt_new_key_pair/2, decrypt_secret_key/2]).
-export([pin_salt/0, pin_to_key/2]).

-include_lib("apptools/include/shorthand.hrl").

%% Exported: digest_password

-spec digest_password(binary()) -> binary().

digest_password(Password) ->
    Salt = crypto:strong_rand_bytes(32),
    DigestPassword = crypto:hash(sha256, [Salt, Password]),
    ?l2b([Salt, DigestPassword]).

%% Exported: check_digested_password

-spec check_digested_password(binary(), binary()) -> boolean().

check_digested_password(Password, <<Salt:32/binary, DigestPassword/binary>>) ->
    crypto:hash(sha256, [Salt, Password]) == DigestPassword.

%% Exported: encrypt_new_key_pair

encrypt_new_key_pair(Key, Nym) ->
    {PublicKey, SecretKey} = elgamal:generate_key_pair(Nym),
    PublicKeyBin = elgamal:public_key_to_binary(PublicKey),
    SecretKeyBin = elgamal:secret_key_to_binary(SecretKey),
    Nonce = enacl:randombytes(enacl:secretbox_NONCEBYTES()),
    EncryptedSecretKey = enacl:secretbox(SecretKeyBin, Nonce, Key),
    {PublicKeyBin, <<Nonce/binary, EncryptedSecretKey/binary>>}.

%% Exported: decrypt_secret_key

decrypt_secret_key(Key, NonceAndEncryptedSecretKey) ->
    NonceSize = enacl:secretbox_NONCEBYTES(),
    <<Nonce:NonceSize/binary, EncryptedSecretKey/binary>> =
        NonceAndEncryptedSecretKey,
    enacl:secretbox_open(EncryptedSecretKey, Nonce, Key).

%% Exported: pin_salt

pin_salt() ->
    enacl:randombytes(enacl:pwhash_SALTBYTES()).

%% Exported: pin_to_key

pin_to_key(Pin, Salt) ->
    enacl:pwhash(Pin, Salt, enacl:secretbox_KEYBYTES()).
