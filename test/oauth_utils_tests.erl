-module(oauth_utils_tests).

-include_lib("eunit/include/eunit.hrl").


main_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [
      fun is_authorized/1,
      fun get_header_params/1,
      fun check_params/1,
      fun get_consumer_key/1,
      fun verify/1,
      fun nonce_expire/1
     ]}.


setup() ->
    error_logger:tty(false),
    ok = oauth_utils:init(1, 500).


teardown(_) ->
    ets:delete(oauth_nonce).


is_authorized(_) ->
    Result1 = oauth_utils:is_authorized('GET', "http://localhost:8000", "/foo", [{"oauth_version","1.0"}, {"oauth_nonce","aupPmkqRYvOml+MLR7JlL6Syx7dL8EcTah9Aoyh5HY0="}, {"oauth_timestamp","1401710539"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"bar","baz"}], "", fun consumer_lookup/1),
    Result2 = oauth_utils:is_authorized('GET', "http://localhost:8000", "/foo", [{"oauth_signature","w6RbTkvBEks0XIkt/HqkEudRvQ8="}, {"oauth_version","1.0"}, {"oauth_nonce","aupPmkqRYvOml+MLR7JlL6Syx7dL8EcTah9Aoyh5HY0="}, {"oauth_timestamp","1401710539"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key2"}, {"bar","baz"}], "", fun consumer_lookup/1),
    Result3 = oauth_utils:is_authorized('GET', "http://localhost:8000", "/foo", [{"oauth_signature","w6RbTkvBEks0XIkt/HqkEudRvQ8="}, {"oauth_version","1.0"}, {"oauth_nonce","aupPmkqRYvOml+MLR7JlL6Syx7dL8EcTah9Aoyh5HY0="}, {"oauth_timestamp","1401710539"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"bar","baz"}], "", fun consumer_lookup/1),
    Result4 = oauth_utils:is_authorized('GET', "http://localhost:8000", "/foo", [{"bar","baz"}], "OAuth oauth_signature=\"ImJG%2B%2FSO9K9CuxSWBkrvDNL4Tio%3D\", oauth_version=\"1.0\", oauth_nonce=\"ABD0Pe6ga2jAfI0lyG8dVRoQUyJuzv9d%2Fm1FSgn8K3k%3D\", oauth_timestamp=\"1401710539\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"key\"", "secret"),
    Result5 = oauth_utils:is_authorized('POST', "http://localhost:8000", "/foo", [], "OAuth oauth_signature=\"VDLo1TGwr6orIvj0rKJbp4YB%2BtI%3D\", oauth_version=\"1.0\", oauth_nonce=\"dT1lilc1CeN4181AgTpySpaXdTPR484EOZyP%2BWmY4Ww%3D\", oauth_timestamp=\"1401710539\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"key\"", "secret"),
    [
     ?_assertEqual({error, "oauth_signature must be specified"}, Result1),
     ?_assertEqual({error, "oauth_consumer_key invalid"}, Result2),
     ?_assertEqual(ok, Result3),
     ?_assertEqual(ok, Result4),
     ?_assertEqual(ok, Result5)
    ].


get_header_params(_) ->
    Result1 = oauth_utils:get_header_params("foo=\"bar\", fiz=\"buz\""),
    Result2 = oauth_utils:get_header_params("oauth   foo=\"bar\", fiz=\"buz\""),
    Result3 = oauth_utils:get_header_params("OAuth foo=\"bar\", fiz=\"buz\""),
    Result4 = oauth_utils:get_header_params("OAuth realm=\"Kings landing\", foo=\"bar\", fiz=\"buz\""),
    [?_assertEqual([{"foo","bar"}, {"fiz","buz"}], Result) || Result <- [Result1, Result2, Result3, Result4]].


check_params(_) ->
    Result1 = oauth_utils:check_params([]),
    Result2 = oauth_utils:check_params([{"oauth_consumer_key","a"}]),
    Result3 = oauth_utils:check_params([{"oauth_consumer_key","a"}, {"oauth_signature_method","b"}]),
    Result4 = oauth_utils:check_params([{"oauth_consumer_key","a"}, {"oauth_signature_method","b"}, {"oauth_signature","c"}]),
    Result5 = oauth_utils:check_params([{"oauth_consumer_key","a"}, {"oauth_signature_method","b"}, {"oauth_signature","c"}, {"oauth_timestamp","d"}]),
    Result6 = oauth_utils:check_params([{"oauth_consumer_key","a"}, {"oauth_signature_method","b"}, {"oauth_signature","c"}, {"oauth_timestamp","d"}, {"oauth_nonce","e"}]),
    Result7 = oauth_utils:check_params([{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","c"}, {"oauth_timestamp","d"}, {"oauth_nonce","e"}, {"oauth_version","f"}]),
    Result8 = oauth_utils:check_params([{"oauth_consumer_key","a"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_signature","c"}, {"oauth_timestamp","d"}, {"oauth_nonce","e"}, {"oauth_version","1.0"}]),
    [
     ?_assertEqual({error, "oauth_consumer_key must be specified"}, Result1),
     ?_assertEqual({error, "oauth_signature_method must be specified"}, Result2),
     ?_assertEqual({error, "oauth_signature must be specified"}, Result3),
     ?_assertEqual({error, "oauth_timestamp must be specified"}, Result4),
     ?_assertEqual({error, "oauth_nonce must be specified"}, Result5),
     ?_assertEqual({error, "oauth_signature_method must be HMAC-SHA1"}, Result6),
     ?_assertEqual({error, "oauth_version must be 1.0"}, Result7),
     ?_assertEqual(ok, Result8)
    ].


get_consumer_key(_) ->
    Result1 = oauth_utils:get_consumer_key([]),
    Result2 = oauth_utils:get_consumer_key([{"oauth_consumer_key","a"}]),
    [
     ?_assertEqual(false, Result1),
     ?_assertEqual("a", Result2)
    ].


verify(_) ->
     Result1 = oauth_utils:verify('GET', "http://localhost:8000", "/foo", [{"oauth_signature","GX/yL/JS4+pDfYUfkq3jwe+BLtQ="}, {"oauth_version","1.0"}, {"oauth_nonce","163yQFdkKOjlFTNAdfLg9PMuQUeJEJaremtOVu1TTho="}, {"oauth_timestamp","1401708910"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"oauth_token",""}, {"bar","baz"}], "secret"),
    Result2 = oauth_utils:verify('GET', "http://localhost:8000", "/foo", [{"oauth_signature","w6RbTkvBEks0XIkt/HqkEudRvQ8="}, {"oauth_version","1.0"}, {"oauth_nonce","aupPmkqRYvOml+MLR7JlL6Syx7dL8EcTah9Aoyh5HY0="}, {"oauth_timestamp","1401710539"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"bar","baz"}], "secret"),
    Result3 = oauth_utils:verify('GET', "http://localhost:8000", "/foo", [{"oauth_signature","w6RbTkvBEks0XIkt/HqkEudRvQ8="}, {"oauth_version","1.0"}, {"oauth_nonce","aupPmkqRYvOml+MLR7JlL6Syx7dL8EcTah9Aoyh5HY0="}, {"oauth_timestamp","1401710539"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"bar","baz"}], "secret"),
    Result4 = oauth_utils:verify('GET', "http://localhost:8000", "/foo", [{"oauth_signature","bogus"}, {"oauth_version","1.0"}, {"oauth_nonce","ABD0Pe6ga2jAfI0lyG8dVRoQUyJuzv9d/m1FSgn8K3k,"}, {"oauth_timestamp","1401710539"}, {"oauth_signature_method","HMAC-SHA1"}, {"oauth_consumer_key","key"}, {"bar","baz"}], "secret"),
    [
     ?_assertEqual(ok, Result1),
     ?_assertEqual(ok, Result2),
     ?_assertEqual({error, "oauth_nonce has been used"}, Result3),
     ?_assertEqual({error, "oauth_signature invalid"}, Result4)
    ].


nonce_expire(_) ->
     Result1 = oauth_utils:verify_nonce([{"oauth_nonce","a"}]),
     Result2 = oauth_utils:verify_nonce([{"oauth_nonce","a"}]),
     timer:sleep(2000),
     Result3 = oauth_utils:verify_nonce([{"oauth_nonce","a"}]),
    [
     ?_assertEqual(ok, Result1),
     ?_assertEqual({error, "oauth_nonce has been used"}, Result2),
     ?_assertEqual(ok, Result3)
    ].


consumer_lookup("key") -> {ok, "secret"};
consumer_lookup(_)     -> error.
