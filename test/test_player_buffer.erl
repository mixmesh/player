-module(test_player_buffer).
-export([start/0]).

-include("../include/player_buffer.hrl").
-include_lib("elgamal/include/elgamal.hrl").

start() ->
    file:delete("/tmp/db"),
    {ok, BufferHandle} = player_buffer:new(<<"/tmp">>),
    ?PLAYER_BUFFER_MAX_SIZE = player_buffer:size(BufferHandle),
    EncryptedData =
        elgamal:urandomize(crypto:strong_rand_bytes(?ENCODED_SIZE)),
    ok = replace_messages(BufferHandle, 0, EncryptedData, 50),
    {ok, Reservation, _ReservedMessage} = player_buffer:reserve(BufferHandle),
    ok = player_buffer:unreserve(BufferHandle, Reservation),
    {ok, Reservation2, _ReserverdeMessage2} = player_buffer:reserve(BufferHandle),
    ReplacementMessage = <<0:64/unsigned-integer, EncryptedData/binary>>,
    {ok, Index} = player_buffer:swap(
                    BufferHandle, Reservation2, ReplacementMessage),
    {ok, ReplacementMessage} = player_buffer:inspect(BufferHandle, Index),
    ?PLAYER_BUFFER_MAX_SIZE = player_buffer:size(BufferHandle).

replace_messages(_BufferHandle, _MessageId, _EncryptedData, 0) ->
    ok;
replace_messages(BufferHandle, MessageId, EncryptedData, K) ->
    Message = <<MessageId:64/unsigned-integer, EncryptedData/binary>>,
    Index = player_buffer:replace(BufferHandle, Message),
    true = is_integer(Index),
    ?PLAYER_BUFFER_MAX_SIZE = player_buffer:size(BufferHandle),
    replace_messages(BufferHandle, MessageId, EncryptedData, K - 1).
