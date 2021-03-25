%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Handle lock/unlock of secret key and
%%%    encrypt and decrypt of data.
%%% @end
%%% Created : 19 Mar 2021 by Tony Rogvall <tony@rogvall.se>

-module(player_crypto_serv).

-export([start_link/4, stop/1]).
-export([decrypt/2, encrypt/3]).
-export([lock/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").

-define(HASH_ALG, sha256).

-record(state,
	{
	 parent :: pid(),
	 store  :: erlang:tid(),
	 count = 0 :: integer(),
	 locked = true :: boolean(),
	 backoff = false :: boolean(),
	 backoff_tmr :: reference(),
	 attempts = 0 :: integer(),
	 pinsalt   :: binary(), %% salt
	 secretkey :: binary()  %% encrypted!
	}).

%% max time in ms between keys. (fixme)
-define(KEY_WAIT_TIME, 5000).
%% max time for pin code entry in ms (fixme)
-define(PINCODE_WAIT_TIME, 20000).
%% min back-off time in ms, for failed input attempt
-define(BACK_OF_TIME_1, 3).     %% first wait 3s
-define(BACK_OF_TIME_2, 4).     %% first wait 4s
-define(BACK_OF_TIME_3, 5).     %% first wait 5s
-define(BACK_OF_TIME_4, 10).    %% first wait 10s
-define(BACK_OF_TIME_5, 60).    %% first wait 1m
-define(BACK_OF_TIME_6, 3400).  %% first wait 1h
-define(BACK_OF_TIME_7, 86400).  %% max wait one day

%% Xbus usage:
%%
%% INPUT
%%
%% "mixmesh.pincode.hdigit" <digest>
%%   Each digit is encoded and hashed from keyboard to 
%%   any one listening (owning the shared decode key) then the
%%   digit is decoded and used in the pincode 
%%
%% "mixmesh.pincode.digit" <digit>
%%   Testing only
%%
%% OUTPUT
%%
%% "mixmesh.pincode.locked" <boolean>
%%   Set when a matching pin code can unlock the secret key
%%
%% "mixmesh.pincode.backoff" <boolean>
%%   Set when wrong pin code was entered, kind off exponential style
%%   back-off
%%
%%

start_link(PinSalt,EncryptedSecretKey, 
	   SharedDecodeKey, SessionDecodeKey) ->
    ?spawn_server(
       fun(Parent) ->
	       init(Parent,
		    PinSalt,EncryptedSecretKey, 
		    SharedDecodeKey, SessionDecodeKey)
       end,
       fun message_handler/1).

stop(Pid) ->
    serv:call(Pid, stop).

lock(Pid) ->
    serv:call(Pid, lock).

decrypt(Pid, Message) ->
    serv:call(Pid, {decrypt, Message}).

encrypt(Pid, Message, PublicKey) ->
    serv:call(Pid, {encrypt, Message, PublicKey}).

init(Parent,
     PinSalt,EncryptedSecretKey, 
     SharedDecodeKey, SessionDecodeKey) ->
    Store = ets:new(key_store, [private]), %% do not peek
    ets:insert(Store, {shared, SharedDecodeKey}),
    ets:insert(Store, {session, SessionDecodeKey}),
    ets:insert(Store, {session0, SessionDecodeKey}),
    ets:insert(Store, {key, <<>>}),
    ets:insert(Store, {pin, "000000"}),
    xbus:pub_meta(<<"mixmesh.pincode.hdigit">>, [{unit, "binary"}]),
    xbus:pub_meta(<<"mixmesh.pincode.digit">>, [{unit, "char"}]),
    xbus:pub_meta(<<"mixmesh.pincode.backoff">>, [{unit, "boolean"}]),
    xbus:pub_meta(<<"mixmesh.pincode.locked">>, [{unit, "boolean"}]),
    xbus:pub(<<"mixmesh.pincode.backoff">>, false),
    xbus:pub(<<"mixmesh.pincode.locked">>, true),
    xbus:sub(<<"mixmesh.pincode.digit">>), %% TESTING
    xbus:sub(<<"mixmesh.pincode.hdigit">>),
    {ok, #state{parent = Parent,
                store  = Store,
		pinsalt   = PinSalt,
		secretkey = EncryptedSecretKey
	       }}.

message_handler(State) ->
    receive
        {call, From, stop} ->
            {stop, From, ok};

        {call, From, lock} ->
	    ets:insert(State#state.store, {key, <<>>}),
	    xbus:pub(<<"mixmesh.pincode.locked">>, true),
	    {reply, From, ok, State#state { count = 0, locked = true }};

	{call, From, {decrypt, Message}} ->
	    %% FIXME: add counter for activity and stats
	    if State#state.locked ->
		    {reply, From, {error,locked}};
	       true ->
		    [{key, SecretKey}] = ets:lookup(State#state.store, key),
		    case elgamal:udecrypt(Message, SecretKey) of
			mismatch ->
			    {reply, From, {error,mismatch}};
			Reply ->
			    {reply, From, {ok,Reply}}
		    end
	    end;
	
	{call, From, {encrypt, Message, PublicKey}} ->
	    %% FIXME: add counter for activity and stats
	    if State#state.locked ->
		    {reply, From, {error,locked}};
	       true ->
		    [{key, SecretKey}] = ets:lookup(State#state.store, key),
		    Reply = elgamal:uencrypt(Message, PublicKey, SecretKey),
		    {reply, From, {ok,Reply}}
	    end;
	    
	{xbus, <<"mixmesh.pincode.hdigit">>, #{ value := SHi }} ->
	    {noreply, handle_key(SHi, State)};

	%% ONLY TESTING - REMOVE ME 
	{xbus, <<"mixmesh.pincode.digit">>, #{ value := D }} ->
	    {noreply, handle_digit(D, State)};

	{timeout, Ref, backoff_done} when State#state.backoff_tmr =:= Ref ->
	    xbus:pub(<<"mixmesh.pincode.backoff">>, false),
	    {noreply, State#state { backoff = false, backoff_tmr = undefined }};

        {system, From, Request} ->
            {system, From, Request};

	%% not using neighbout info
	{neighbour_workers, _NeighbourWorkers} ->
	    noreply;

        {'EXIT', Pid, Reason} when Pid =:= State#state.parent ->
            exit(Reason);

        {'EXIT', _Pid, killed} ->
	    %% player_serv killed our child - spawn_link....
	    noreply;

        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

handle_key(SHi, State=#state{ store = Store }) ->
    [{shared, S0}] = ets:lookup(Store, shared),
    [{session, H0}] = ets:lookup(Store, session),
    case decode_digit($0,S0,H0,SHi) of
	false ->
	    %% restart decoding?
	    %% [{session,SS0}] = ets:lookup(Store, session0),
	    %% ets:inster(Store, {session,SS0}),
	    State;
	{true,D} ->
	    H1 = crypto:hash(?HASH_ALG, [H0,D]),
	    ets:insert(Store, {session,H1}),
	    handle_digit(D, State)
    end.

handle_digit(D, State = #state { store = Store} ) when
      State#state.locked, not State#state.backoff ->
    [{pin,Pin0}] = ets:lookup(Store, pin),
    {_, Pin1} = lists:split(1, Pin0),
    Pin = Pin1++[D],
    ets:insert(Store, {pin,Pin}),
    Count1 = State#state.count + 1,
    io:format("Pin: ~p\n", [Pin]),
    if Count1 >= 6 ->
	    %% FIXME allow 6 digits more before backoff!
	    case try_unlock(Pin, State) of
		{ok,DecryptedSecretKey} ->
		    io:format("Unlocked\n", []),
		    ets:insert(Store, {key, DecryptedSecretKey}),
		    xbus:pub(<<"mixmesh.pincode.locked">>, false),
		    State#state { attempts = 0, count = 0, locked = false };
		_ ->
		    ets:insert(Store, {key, <<>>}),
		    xbus:pub(<<"mixmesh.pincode.backoff">>, true),
		    Attempts = State#state.attempts + 1,
		    BackoffTime = backoff_ms(Attempts),
		    io:format("Unlock fail attempts=~w, backoff=~ws\n", 
			      [Attempts, BackoffTime div 1000]),
		    Tmr = erlang:start_timer(BackoffTime, self(), backoff_done),
		    State#state { count = 0,  %% rolling?? or enter key?
				  locked = true,
				  backoff = true,
				  backoff_tmr = Tmr,
				  attempts = Attempts }
	    end;
       true ->
	    State#state { count = Count1 }
    end;
handle_digit(_D, State) ->
    State.

try_unlock(Pin, State) ->
    SharedKey = player_crypto:pin_to_shared_key(Pin, State#state.pinsalt),
    player_crypto:shared_decrypt(SharedKey, State#state.secretkey).

%% When a hashed digit is received we loop and try to decode it
decode_digit(D,S0,H,SHi) when D =< $9 ->
    case crypto:hash(?HASH_ALG, [S0,H,D]) of
	SHi ->
	    D;
	_ ->
	    decode_digit(D+1,S0,H,SHi)
    end;
decode_digit(_,_,_,_) ->
    false.

backoff_ms(Attempts) ->
    backoff_s(Attempts)*1000.

backoff_s(1) -> ?BACK_OF_TIME_1;
backoff_s(2) -> ?BACK_OF_TIME_2;
backoff_s(3) -> ?BACK_OF_TIME_3;
backoff_s(4) -> ?BACK_OF_TIME_4;
backoff_s(5) -> ?BACK_OF_TIME_5;
backoff_s(6) -> ?BACK_OF_TIME_6;
backoff_s(_) -> ?BACK_OF_TIME_7.
