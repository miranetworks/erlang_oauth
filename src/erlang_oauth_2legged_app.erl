%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc Callbacks for the erlang_oauth_2legged application.

-module(erlang_oauth_2legged_app).
-author('author <author@example.com>').

-behaviour(application).
-export([start/2,stop/1]).


%% @spec start(_Type, _StartArgs) -> ServerRet
%% @doc application start callback for erlang_oauth_2legged.
start(_Type, _StartArgs) ->
    ok = oauth_utils:init(),
    erlang_oauth_2legged_sup:start_link().

%% @spec stop(_State) -> ServerRet
%% @doc application stop callback for erlang_oauth_2legged.
stop(_State) ->
    ok.
