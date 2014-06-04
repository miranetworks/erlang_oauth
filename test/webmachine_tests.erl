-module(webmachine_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").
-include_lib("webmachine/include/webmachine.hrl").


main_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [
      fun get/1,
      fun post/1
     ]}.


setup() ->
    error_logger:tty(false),
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(webmachine),
    {ok, _} = webmachine_mochiweb:start([{name, test},
                                         {ip, "127.0.0.1"},
                                         {port, 8000},
                                         {log_dir, "."},
                                         {dispatch, [{['*'], ?MODULE, []}]}]),
    ok = oauth_utils:init().


teardown(_) ->
    ets:delete(oauth_nonce),
    ok = webmachine_mochiweb:stop(test_mochiweb),
    ok = application:stop(webmachine),
    ok = application:stop(inets).


get(_) ->
    {ok, {{_,Status1,_}, Headers1, _}} = httpc:request("http://localhost:8000/foo?bar=baz"),
    Result2 = httpc:request(get, {"http://localhost:8000/foo?oauth_signature=ELKs2q5yaq3wTEewquZWYiVPApQ%3D&oauth_version=1.0&oauth_nonce=zpkp%2F67wLWiepOdYlZyatrzr2c5lGc3GQCmY3t9JOF8%3D&oauth_timestamp=1401707835&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baz", []}, [], [{full_result,false}]),
    Result3 = httpc:request(get, {"http://localhost:8000/foo?bar=baz", [{"Authorization","OAuth realm=\"http://localhost:8000\", oauth_signature=\"wFNFxctVaILoH%2Bariy9x%2FDlLLOs%3D\", oauth_version=\"1.0\", oauth_nonce=\"rOWbXbm9iy%2FMXSTr8iUAwuhWuHOtxBOX71J6UbT9huE%3D\", oauth_timestamp=\"1401707835\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"key\""}]}, [], [{full_result,false}]),
    [
     ?_assertMatch({401, "OAuth realm=\"http://localhost:8000\""}, {Status1, proplists:get_value("www-authenticate", Headers1)}),
     ?_assertMatch({ok, {200, _}}, Result2),
     ?_assertMatch({ok, {200, _}}, Result3)
    ].


post(_) ->
    {ok, {{_,Status1,_}, Headers1, _}} = httpc:request(post, {"http://localhost:8000/foo", [], "text/plain", ""}, [], []),
    Result2 = httpc:request(post, {"http://localhost:8000/foo", [{"Authorization","OAuth oauth_signature=\"mD3gba6aazbnI10t6UMEuVWH9y4%3D\", oauth_version=\"1.0\", oauth_nonce=\"hX3EJrxjPeA%2FD5iLnSt8P7Ts7JejjZ50Ibdx6Y5bD8E%3D\", oauth_timestamp=\"1401707835\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"key\""}], "text/plain", ""}, [], [{full_result,false}]),
    [
     ?_assertMatch({401, "OAuth realm=\"http://localhost:8000\""}, {Status1, proplists:get_value("www-authenticate", Headers1)}),
     ?_assertMatch({ok, {200,_}}, Result2)
    ].


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Test helpers
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(REALM, "http://localhost:8000").


init([]) ->
    {ok, []}.


allowed_methods(ReqData, State) ->
    {['GET', 'POST'], ReqData, State}.


is_authorized(ReqData, State) ->
    Method = wrq:method(ReqData),
    Path = wrq:path(ReqData),
    QueryParams = wrq:req_qs(ReqData),
    AuthHeader = wrq:get_req_header("Authorization", ReqData),
    case oauth_utils:is_authorized(Method, ?REALM, Path, QueryParams, AuthHeader, fun consumer_lookup/1) of
        ok              -> {true, ReqData, State};
        {error, Reason} -> unauthorized(Reason, ReqData, State)
    end.


unauthorized(Body, ReqData, State) ->
    {"OAuth realm=\"" ?REALM "\"", wrq:set_resp_header("Content-Type", "text/plain", wrq:set_resp_body(Body, ReqData)), State}.


content_types_provided(ReqData, State) ->
    {[{"text/plain", to_text}], ReqData, State}.


to_text(ReqData, State) ->
    {"hello", ReqData, State}.


process_post(ReqData, State) ->
    {true, wrq:set_resp_header("Content-Type", "text/plain", wrq:set_resp_body("bla", ReqData)), State}.


consumer_lookup("key") -> {ok, "secret"};
consumer_lookup(_)     -> error.
