-module(mail_serv).
-export([start_link/2, stop/1]).
-export([send_mail/4]).

%% NOTE: This server is typically used for debugging purposes when we
%%       need to send bulk emails.
%% NOTE: This server requires
%%       http://www.jetmore.org/john/code/swaks/ to be installed.

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").

-record(state,
        {parent                    :: pid(),
         name                      :: binary(),
         smtp_address              :: {inet:ip4_address(), inet:port_number()},
         smtp_password = <<"baz">> :: binary()}).

%% Exported: start_link

start_link(Name, SmtpAddress) ->
    ?spawn_server(
       fun(Parent) -> init(Parent, Name, SmtpAddress) end,
       fun message_handler/1).

%% Exported: stop

stop(Pid) ->
    serv:call(Pid, stop).

%% Exported: send_mail

send_mail(Pid, RecipientName, PickedAsSource, Letter) ->
    serv:cast(Pid, {send_mail, RecipientName, PickedAsSource, Letter}).

%%
%% Server
%%

init(Parent, Name, SmtpAddress) ->
    ?daemon_tag_log(system, "SMTP server for ~s has been started", [Name]),
    {ok, #state{parent = Parent, name = Name, smtp_address = SmtpAddress}}.

message_handler(#state{parent = Parent,
                       name = Name,
                       smtp_address = {SmtpIpAddress, SmtpPort},
                       smtp_password = SmtpPassword}) ->
    receive
        {call, From, stop} ->
            {stop, From, ok};
        {cast, {send_mail, RecipientName, PickedAsSource, Letter}} ->
            "" = swaks(Name, RecipientName, SmtpIpAddress, SmtpPort,
                       SmtpPassword, PickedAsSource, Letter),
            noreply;
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            exit(Reason);
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

swaks(From, To, IpAddress, Port, Password, PickedAsSource, Body) ->
    Command =
        io_lib:format(
          "swaks --from ~s --to ~s --server ~s:~w --auth LOGIN --auth-user ~s --auth-password ~s --body '~s' --silent",
          [From, To, inet_parse:ntoa(IpAddress), Port, From, Password, Body]),
    FinalCommand =
        if
            PickedAsSource ->
                [Command, " --add-header 'X-Obscrete-Trace: yes'"];
            true ->
                Command
        end,
    ?dbg_log({swaks, FinalCommand}),
    os:cmd(FinalCommand).
