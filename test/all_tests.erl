-module(all_tests).

-include_lib("eunit/include/eunit.hrl").


two_legged_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              no_token(),
              empty_token(),
              version(),
              signature_method(),
              missing_timestamp(),
              nonce(),
              consumer_key(),
              signature()
             ]
     end}.


start() ->
    ok = erlang_oauth:start().
 

stop(_) ->
    ok = erlang_oauth:stop().
 

http_get(Url) ->
    httpc:request(get, {Url, []}, [], [{full_result,false}]).


no_token() ->
    Url = "http://localhost:8000/foo?oauth_signature=3oqngFeX5P0snvSf2DGfveryQ0Q%3D&oauth_version=1.0&oauth_nonce=tOc6sVBfcIqSW4xBCdvxW9L3DbEdWBg44Q3zJPJXFoA%3D&oauth_timestamp=1392288554&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baz",
    [?_assertEqual({ok, {200,"hello world"}}, http_get(Url))].


empty_token() ->
    Url = "http://localhost:8000/foo?oauth_signature=L8JsJKalZzyZ2Qc6RgOKTMNLcGo%3D&oauth_version=1.0&oauth_nonce=XVfPIXp7b6KDeLq5MgcRw4UNLwueD8cvRLtSfzdRdUg%3D&oauth_timestamp=1392288661&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&oauth_token=&bar=baz",
    [?_assertEqual({ok, {200,"hello world"}}, http_get(Url))].


version() ->
    Url = "http://localhost:8000/foo?oauth_signature=3oqngFeX5P0snvSf2DGfveryQ0Q%3D&oauth_version=2.0&oauth_nonce=tOc6sVBfcIqSW4xBCdvxW9L3DbEdWBg44Q3zJPJXFoA%3D&oauth_timestamp=1392288554&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baz",
    [?_assertEqual({ok, {400,"oauth_version must be 1.0"}}, http_get(Url))].


signature_method() ->
    Url = "http://localhost:8000/foo?oauth_signature=3oqngFeX5P0snvSf2DGfveryQ0Q%3D&oauth_version=1.0&oauth_nonce=tOc6sVBfcIqSW4xBCdvxW9L3DbEdWBg44Q3zJPJXFoA%3D&oauth_timestamp=1392288554&oauth_signature_method=PLAINTEXT&oauth_consumer_key=key&bar=baz",
    [?_assertEqual({ok, {400,"oauth_signature_method must be HMAC-SHA1"}}, http_get(Url))].


missing_timestamp() ->
    Url = "http://localhost:8000/foo?oauth_signature=3oqngFeX5P0snvSf2DGfveryQ0Q%3D&oauth_version=1.0&oauth_nonce=tOc6sVBfcIqSW4xBCdvxW9L3DbEdWBg44Q3zJPJXFoA%3D&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baz",
    [?_assertEqual({ok, {400,"oauth_timestamp must be specified"}}, http_get(Url))].


nonce() ->
    Url = "http://localhost:8000/foo?oauth_signature=3oqngFeX5P0snvSf2DGfveryQ0Q%3D&oauth_version=1.0&oauth_nonce=tOc6sVBfcIqSW4xBCdvxW9L3DbEdWBg44Q3zJPJXFoA%3D&oauth_timestamp=1392288554&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baz",
    [?_assertEqual({ok, {401,"oauth_nonce has been used"}}, http_get(Url))].


consumer_key() ->
    Url = "http://localhost:8000/foo?oauth_signature=6YfAR%2FaB3MBcwSNQ2LlPY1wXpOU%3D&oauth_version=1.0&oauth_nonce=wQtvYVBopEg5oXyuvQ33bPbTEyRc0FHXXylfED3Ly8Q%3D&oauth_timestamp=1392289642&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=yek&bar=baz",
    [?_assertEqual({ok, {401,"oauth_consumer_key invalid"}}, http_get(Url))].


signature() ->
    Url = "http://localhost:8000/foo?oauth_signature=j9s%2F6X4uqBzO1m8S2GODkV1atqc%3D&oauth_version=1.0&oauth_nonce=2wQ8tDkAJVE5E6t4n6RRqbuFM6xDZa9jScDbl4geTEU%3D&oauth_timestamp=1392289664&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=key&bar=baa",
    [?_assertEqual({ok, {401,"oauth_signature invalid"}}, http_get(Url))].
