-module(oauth_utils_tests).

-include_lib("eunit/include/eunit.hrl").
-include("oauth_utils.hrl").


main_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [
      fun parse_auth_header/1,
      fun check_params/1,
      fun verify_nonce/1,
      fun verify_signature/1,
      fun wellformed_request/1,
      fun is_authorized/1,
      fun getters/1
     ]}.


setup() ->
    error_logger:tty(false),
    ok = oauth_utils:init(1, 500).


teardown(_) ->
    ets:delete(oauth_nonce).


parse_auth_header(_) ->
    Result1 = oauth_utils:parse_auth_header(""),
    Result2 = oauth_utils:parse_auth_header("a=\"b\""),
    Result3 = oauth_utils:parse_auth_header("oauth a=\"b\""),
    Result4 = oauth_utils:parse_auth_header("OAuth    a=\"b\",c=\"d\""),
    Result5 = oauth_utils:parse_auth_header("OAuth\ta=\"b\",\r\n c=\"d\", \te=\"f\""),
    Result6 = oauth_utils:parse_auth_header("OAuth foobar"),
    Result7 = oauth_utils:parse_auth_header("OAuth realm=\"kings landing\",a=\"b\",c=\"d\""),
    Result8 = oauth_utils:parse_auth_header(undefined),
    [
     ?_assertEqual({error, "Authorization header malformed"}, Result1),
     ?_assertEqual({error, "Authorization header malformed"}, Result2),
     ?_assertEqual({ok, [{"a","b"}]}, Result3),
     ?_assertEqual({ok, [{"a","b"}, {"c","d"}]}, Result4),
     ?_assertEqual({ok, [{"a","b"}, {"c","d"}, {"e","f"}]}, Result5),
     ?_assertEqual({error, "Authorization header malformed"}, Result6),
     ?_assertEqual({ok, [{"a","b"}, {"c","d"}]}, Result7),
     ?_assertEqual({ok, []}, Result8)
    ].


check_params(_) ->
    Result1 = oauth_utils:check_params(#oauth_req{params=[]}),
    Result2 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}]}),
    Result3 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","b"}]}),
    Result4 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}]}),
    Result5 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}]}),
    Result6 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}]}),
    Result7 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}]}),
    Result8 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}, {"oauth_version","e"}]}),
    Result9 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}, {"oauth_version","1.0"}, {"foo","bar"}]}),
    Result10 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}, {"oauth_version","1.0"}, {"foo","bar"}, {"oauth_consumer_key","A"}]}),
    Result11 = oauth_utils:check_params(#oauth_req{params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}, {"oauth_version","1.0"}, {"oauth_version","2.0"}, {"foo","bar"}]}),
    [
     ?_assertEqual({error, "oauth_consumer_key must be specified"}, Result1),
     ?_assertEqual({error, "oauth_signature_method must be specified"}, Result2),
     ?_assertEqual({error, "oauth_signature_method must be HMAC-SHA1"}, Result3),
     ?_assertEqual({error, "oauth_signature must be specified"}, Result4),
     ?_assertEqual({error, "oauth_timestamp must be specified"}, Result5),
     ?_assertEqual({error, "oauth_nonce must be specified"}, Result6),
     ?_assertMatch({ok, #oauth_req{consumer_key="a", signature_method="HMAC-SHA1", signature="b", timestamp="c", nonce="d", version="1.0"}}, Result7),
     ?_assertEqual({error, "oauth_version must be 1.0"}, Result8),
     ?_assertMatch({ok, #oauth_req{consumer_key="a", signature_method="HMAC-SHA1", signature="b", timestamp="c", nonce="d", version="1.0"}}, Result9),
     ?_assertEqual({error, "oauth_consumer_key specified more than once"}, Result10),
     ?_assertEqual({error, "oauth_version specified more than once"}, Result11)
    ].


verify_nonce(_) ->
    Result1 = oauth_utils:verify_nonce(#oauth_req{nonce="a"}),
    Result2 = oauth_utils:verify_nonce(#oauth_req{nonce="a"}),
    timer:sleep(2000),
    Result3 = oauth_utils:verify_nonce(#oauth_req{nonce="a"}),
    [
     ?_assertEqual(ok, Result1),
     ?_assertEqual({error, "oauth_nonce has been used"}, Result2),
     ?_assertEqual(ok, Result3)
    ].


verify_signature(_) ->
    Result1 = oauth_utils:verify_signature("http://localhost:8000", "secret", #oauth_req{method='GET', path="/foo", params=[{"oauth_signature","afYEmKQmDMK/UeC6U7mB6rDy0J8="}, {"oauth_version","1.0"}, {"oauth_nonce","XjZbboCk8P290G0G0xN5zXTNDLtmPA/zqQMCERWvE64="}, {"oauth_timestamp","1402054710"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}], consumer_key="key", signature="afYEmKQmDMK/UeC6U7mB6rDy0J8="}),
    Result2 = oauth_utils:verify_signature("http://localhost:8000", "secret", #oauth_req{method='GET', path="/foo", params=[{"oauth_signature","yanscSW/0Go6iwd4lA4L5nGBI24="}, {"oauth_version","1.0"}, {"oauth_nonce","EkTiU5SVv8Vjdo0tNV5XOPiBZNT1tJSzOknGaDpFs4U="}, {"oauth_timestamp","1402055108"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"oauth_token",""}, {"bar","baz"}], consumer_key="key", signature="yanscSW/0Go6iwd4lA4L5nGBI24="}),
    Result3 = oauth_utils:verify_signature("http://localhost:8000", "secret", #oauth_req{method='POST', path="/foo", params=[{"oauth_signature","Mnse+wxJ/JA32Ni/4G+KsJDIX3M="}, {"oauth_version","1.0"}, {"oauth_nonce","NUJ/Pw8x09eFIzp+7n3SzD1tktwD+R4Vt1dtZg60TIo="}, {"oauth_timestamp","1402055216"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}], consumer_key="key", signature="Mnse+wxJ/JA32Ni/4G+KsJDIX3M="}),
    Result4 = oauth_utils:verify_signature("http://localhost:8000", "guess", #oauth_req{method='POST', path="/foo", params=[{"oauth_signature","Mnse+wxJ/JA32Ni/4G+KsJDIX3M="}, {"oauth_version","1.0"}, {"oauth_nonce","NUJ/Pw8x09eFIzp+7n3SzD1tktwD+R4Vt1dtZg60TIo="}, {"oauth_timestamp","1402055216"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}], consumer_key="key", signature="Mnse+wxJ/JA32Ni/4G+KsJDIX3M="}),
    [
     ?_assertEqual(ok, Result1),
     ?_assertEqual(ok, Result2),
     ?_assertEqual(ok, Result3),
     ?_assertEqual({error, "oauth_signature invalid"}, Result4)
    ].


wellformed_request(_) ->
    Result1 = oauth_utils:wellformed_request(m, "p", [], ""),
    Result2 = oauth_utils:wellformed_request(m, "p", [{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}], undefined),
    Result3 = oauth_utils:wellformed_request(m, "p", [{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}, {"foo","bar"}], undefined),
    Result4 = oauth_utils:wellformed_request(m, "p", [], "OAuth oauth_consumer_key=\"a\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"b\", oauth_timestamp=\"c\", oauth_nonce=\"d\""),
    Result5 = oauth_utils:wellformed_request(m, "p", [{"foo","bar"}], "OAuth oauth_consumer_key=\"a\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"b\", oauth_timestamp=\"c\", oauth_nonce=\"d\""),
    [
     ?_assertEqual({error, "Authorization header malformed"}, Result1),
     ?_assertMatch({ok, #oauth_req{
                           query_params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}],
                           params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}]
                          }}, Result2),
     ?_assertMatch({ok, #oauth_req{
                           query_params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}, {"foo","bar"}],
                           params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}, {"foo","bar"}]
                          }}, Result3),
     ?_assertMatch({ok, #oauth_req{
                           query_params=[],
                           params=[{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}]
                          }}, Result4),
     ?_assertMatch({ok, #oauth_req{
                           query_params=[{"foo","bar"}],
                           params=[{"foo","bar"}, {"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","b"}, {"oauth_timestamp","c"}, {"oauth_nonce","d"}]
                          }}, Result5)
    ].


is_authorized(_) ->
    Result1 = oauth_utils:is_authorized("http://localhost:8000", "secret", #oauth_req{method='GET', path="/foo", params=[{"oauth_signature","afYEmKQmDMK/UeC6U7mB6rDy0J8="}, {"oauth_version","1.0"}, {"oauth_nonce","XjZbboCk8P290G0G0xN5zXTNDLtmPA/zqQMCERWvE64="}, {"oauth_timestamp","1402054710"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}], consumer_key="key", signature="afYEmKQmDMK/UeC6U7mB6rDy0J8=", nonce="XjZbboCk8P290G0G0xN5zXTNDLtmPA/zqQMCERWvE64="}),
    Result2 = oauth_utils:is_authorized("http://localhost:8000", "secret", #oauth_req{method='GET', path="/foo", params=[{"oauth_signature","afYEmKQmDMK/UeC6U7mB6rDy0J8="}, {"oauth_version","1.0"}, {"oauth_nonce","XjZbboCk8P290G0G0xN5zXTNDLtmPA/zqQMCERWvE64="}, {"oauth_timestamp","1402054710"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}], consumer_key="key", signature="afYEmKQmDMK/UeC6U7mB6rDy0J8=", nonce="XjZbboCk8P290G0G0xN5zXTNDLtmPA/zqQMCERWvE64="}),
    Result3 = oauth_utils:is_authorized("http://localhost:8000", fun consumer_lookup/1, #oauth_req{method='POST', path="/foo", params=[{"oauth_signature","Mnse+wxJ/JA32Ni/4G+KsJDIX3M="}, {"oauth_version","1.0"}, {"oauth_nonce","NUJ/Pw8x09eFIzp+7n3SzD1tktwD+R4Vt1dtZg60TIo="}, {"oauth_timestamp","1402055216"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}], consumer_key="key", signature="Mnse+wxJ/JA32Ni/4G+KsJDIX3M=", nonce="NUJ/Pw8x09eFIzp+7n3SzD1tktwD+R4Vt1dtZg60TIo="}),
    Result4 = oauth_utils:is_authorized("http://localhost:8000", fun consumer_lookup/1, #oauth_req{method='POST', path="/foo", params=[{"oauth_signature","Mnse+wxJ/JA32Ni/4G+KsJDIX3M="}, {"oauth_version","1.0"}, {"oauth_nonce","NUJ/Pw8x09eFIzp+7n3SzD1tktwD+R4Vt1dtZg60TIo="}, {"oauth_timestamp","1402055216"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","hacker"}], consumer_key="hacker", signature="Mnse+wxJ/JA32Ni/4G+KsJDIX3M=", nonce="NUJ/Pw8x09eFIzp+7n3SzD1tktwD+R4Vt1dtZg60TIo="}),
    [
     ?_assertEqual(ok, Result1),
     ?_assertEqual({error, "oauth_nonce has been used"}, Result2),
     ?_assertEqual(ok, Result3),
     ?_assertEqual({error, "oauth_consumer_key invalid"}, Result4)
    ].


getters(_) ->
    Result1 = oauth_utils:get_other_params(#oauth_req{query_params=[{"oauth_signature","afYEmKQmDMK/UeC6U7mB6rDy0J8="}, {"oauth_version","1.0"}, {"oauth_nonce","XjZbboCk8P290G0G0xN5zXTNDLtmPA/zqQMCERWvE64="}, {"oauth_timestamp","1402054710"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}]}),
    Result2 = oauth_utils:get_other_params(#oauth_req{query_params=[{"oauth_signature","yanscSW/0Go6iwd4lA4L5nGBI24="}, {"oauth_version","1.0"}, {"oauth_nonce","EkTiU5SVv8Vjdo0tNV5XOPiBZNT1tJSzOknGaDpFs4U="}, {"oauth_timestamp","1402055108"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"oauth_token",""}, {"bar","baz"}]}),
    Result3 = oauth_utils:get_consumer_key(#oauth_req{consumer_key="a"}),
    [
     ?_assertEqual([], Result1),
     ?_assertEqual([{"bar","baz"}], Result2),
     ?_assertEqual("a", Result3)
    ].


consumer_lookup("key") -> {ok, "secret"};
consumer_lookup(_)     -> error.
