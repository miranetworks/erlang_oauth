-module(oauth_utils).

-export([
         init/0,
         check_params/1,
         verify/4
        ]).

-type params_t() :: [{string(), string()}].
-type consumer_lookup_fun_t() :: fun((string()) -> {ok, string()} | {error, not_found}).


-spec init() -> ok.
init() ->
    oauth_nonce = ets:new(oauth_nonce, [set, public, named_table]),
    ok.


-spec check_params(params_t()) -> ok | {error, string()}.
check_params(Params) ->
    check_params(missing, Params).


-spec verify(params_t(), string(), string(), consumer_lookup_fun_t()) -> ok | {error, string()}.
verify(Params, Realm, Path, ConsumerLookupFun) ->
    verify(nonce, {Params, Realm, Path, ConsumerLookupFun}).


% Privates
check_params(missing, Params) ->
    case check_required_params(Params) of
        ok    -> check_params(version, Params);
        Error -> Error
    end;

check_params(version, Params) ->
    case lists:keyfind("oauth_version", 1, Params) of
        false      -> check_params(signature, Params);  % unspecified version is fine, assume 1.0
        {_, "1.0"} -> check_params(signature, Params);
        _          -> {error, "oauth_version must be 1.0"}
    end;

check_params(signature, Params) ->
    case lists:keyfind("oauth_signature_method", 1, Params) of
        {_, "HMAC-SHA1"} -> check_params(done, Params);
        _                -> {error, "oauth_signature_method must be HMAC-SHA1"}
    end;

check_params(done, _) -> ok.


check_required_params(Params) -> 
    check_required_params(Params, required_params()).


check_required_params(_, []) -> ok;
check_required_params(Params, [Key | Rest]) ->
    case lists:keytake(Key, 1, Params) of
        {value, _, NewParams} -> check_required_params(NewParams, Rest);
        false                 -> {error, Key ++ " must be specified"}
    end.


required_params() -> 
    [
     "oauth_consumer_key",
     "oauth_signature_method",
     "oauth_signature",
     "oauth_timestamp",
     "oauth_nonce"
    ].


verify(nonce, {Params, Realm, Path, ConsumerLookupFun}) ->
    {_, Nonce} = lists:keyfind("oauth_nonce", 1, Params),
    case nonce_insert(Nonce) of
        true  -> verify(consumer_key, {Params, Realm, Path, ConsumerLookupFun});
        false -> {error, "oauth_nonce has been used"}
    end;

verify(consumer_key, {Params, Realm, Path, ConsumerLookupFun}) ->
    {_, ConsumerKey} = lists:keyfind("oauth_consumer_key", 1, Params),
    case ConsumerLookupFun(ConsumerKey) of
        {ok, ConsumerSecret} -> verify(signature, {Params, Realm, Path, ConsumerKey, ConsumerSecret});
        _                    -> {error, "oauth_consumer_key invalid"}
    end;

verify(signature, {Params, Realm, Path, ConsumerKey, ConsumerSecret}) ->
    {value, {_, Signature}, OtherParams} = lists:keytake("oauth_signature", 1, Params),
    Url = string:concat(Realm, Path),
    Consumer = {ConsumerKey, ConsumerSecret, hmac_sha1},
    case oauth:verify(Signature, "GET", Url, OtherParams, Consumer, "") of
        true  -> verify(done, {});
        false -> {error, "oauth_signature invalid"}
    end;

verify(done, _) -> ok.


nonce_insert(Nonce) when is_list(Nonce) ->
    nonce_insert(list_to_binary(Nonce));

nonce_insert(Nonce) when is_binary(Nonce) ->
    ets:insert_new(oauth_nonce, {Nonce}).
