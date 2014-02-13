%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc erlang_oauth_2legged startup code

-module(erlang_oauth_2legged).
-author('author <author@example.com>').
-export([start/0, start_link/0, stop/0]).

ensure_started(App) ->
    case application:start(App) of
        ok ->
            ok;
        {error, {already_started, App}} ->
            ok
    end.

%% @spec start_link() -> {ok,Pid::pid()}
%% @doc Starts the app for inclusion in a supervisor tree
start_link() ->
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    erlang_oauth_2legged_sup:start_link().

%% @spec start() -> ok
%% @doc Start the erlang_oauth_2legged server.
start() ->
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    application:start(erlang_oauth_2legged).

%% @spec stop() -> ok
%% @doc Stop the erlang_oauth_2legged server.
stop() ->
    Res = application:stop(erlang_oauth_2legged),
    application:stop(webmachine),
    application:stop(mochiweb),
    application:stop(crypto),
    application:stop(inets),
    Res.
