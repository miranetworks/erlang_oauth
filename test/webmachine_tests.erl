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
    Result1 = httpc:request(get, {"http://localhost:8000/foo?bar=baz", []}, [], [{full_result,false}]),
    {ok, {{_,Status2,_}, Headers2, _}} = httpc:request(get, {"http://localhost:8000/foo?oauth_signature=bogus&oauth_version=1.0&oauth_nonce=gl%2B5%2F1iAIHy0GfN4aBylFYdcE%2FM19ymHHJ7u8SUjv3A%3D&oauth_timestamp=1402057724&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baz", []}, [], []),
    Result3 = httpc:request(get, {"http://localhost:8000/foo?oauth_signature=%2B9VEI77vCb%2FeQjEWvWTgTo5gYbo%3D&oauth_version=1.0&oauth_nonce=e3mLruauez%2Fhfzxbtn7pp0Qdq7QoZ726yo5ZTNBg55k%3D&oauth_timestamp=1402057935&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baz", []}, [], [{full_result,false}]),
    Result4 = httpc:request(get, {"http://localhost:8000/foo?bar=baz", [{"Authorization", "OAuth oauth_signature=\"N4WopHYfYiVjE0FeKocwNZ%2FccBI%3D\", oauth_version=\"1.0\", oauth_nonce=\"pdrRkndqATmZW11tgo3dXv5WHr65MlCTMqdqkFL22eM%3D\", oauth_timestamp=\"1402058121\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"key\""}]}, [], [{full_result,false}]), 
    [
     ?_assertMatch({ok, {400, _}}, Result1),
     ?_assertEqual({401, "OAuth realm=\"http://localhost:8000\""}, {Status2, proplists:get_value("www-authenticate", Headers2)}),
     ?_assertMatch({ok, {200, _}}, Result3),
     ?_assertMatch({ok, {200, _}}, Result4)
    ].


post(_) ->
    Result1 = httpc:request(post, {"http://localhost:8000/foo", [], "text/plain", ""}, [], [{full_result,false}]),
    {ok, {{_,Status2,_}, Headers2, _}} = httpc:request(post, {"http://localhost:8000/foo", [{"Authorization", "OAuth oauth_signature=\"bogus\", oauth_version=\"1.0\", oauth_nonce=\"x7mJUsYcvEuEdtokrjIFcSZB0i8hPj6AYdN1lx0tdAw%3D\", oauth_timestamp=\"1402058428\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"key\""}], "text/plain", ""}, [], []),
    Result3 = httpc:request(post, {"http://localhost:8000/foo", [{"Authorization", "OAuth oauth_signature=\"scsPMW%2BNu9yCCDNMOQvviZsX1xw%3D\", oauth_version=\"1.0\", oauth_nonce=\"8pp6uMDlLRJduRquPYRqBHlL3CmmCQNbmSYgonwVEKw%3D\", oauth_timestamp=\"1402058532\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"key\""}], "text/plain", ""}, [], [{full_result,false}]),
    [
     ?_assertMatch({ok, {400, _}}, Result1),
     ?_assertEqual({401, "OAuth realm=\"http://localhost:8000\""}, {Status2, proplists:get_value("www-authenticate", Headers2)}),
     ?_assertMatch({ok, {200, _}}, Result3)
    ].


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Test helpers
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(REALM, "http://localhost:8000").


init([]) ->
    {ok, []}.


allowed_methods(ReqData, State) ->
    {['GET', 'POST'], ReqData, State}.


malformed_request(ReqData, State) ->
    case oauth_utils:wellformed_request(webmachine, ReqData) of
        {ok, OAuth} -> 
            _OtherParams = oauth_utils:get_other_params(OAuth),
            % check_params(_OtherParams)...
            {false, ReqData, {OAuth}};
        {error, Reason} -> malformed(Reason, ReqData, State)
    end.


malformed(Body, ReqData, State) ->
    {true, wrq:set_resp_header("Content-Type", "text/plain", wrq:set_resp_body(Body, ReqData)), State}.


is_authorized(ReqData, State={OAuth}) ->
    case oauth_utils:is_authorized(?REALM, fun consumer_lookup/1, OAuth) of
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
