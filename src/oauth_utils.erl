-module(oauth_utils).

-export([
         init/0,
         check_params/1,
         get_consumer_key/1,

         verify/4,
         verify_nonce/4,
         verify_signature/4
        ]).

%% OAuth parameters
-define(CONSUMER_KEY_PARAM, "oauth_consumer_key").
-define(SIGNATURE_METHOD_PARAM, "oauth_signature_method").
-define(SIGNATURE_PARAM, "oauth_signature").
-define(TIMESTAMP_PARAM, "oauth_timestamp").
-define(NONCE_PARAM, "oauth_nonce").
-define(VERSION_PARAM, "oauth_version").

-type params_t() :: [{string(), string()}].

-spec init() -> ok.
init() ->
    oauth_nonce = ets:new(oauth_nonce, [set, public, named_table]),
    ok.


%%
%% @doc Verify an oauth 1.0 request by checking the nonce and signature.
%%
%% See verify_nonce/4 and verify_signature/4
%%
-spec verify(string(), string(), params_t(), string()) -> ok | {error, string()}.

verify(Realm, Path, Params, ConsumerSecret) ->
    case verify_nonce(Realm, Path, Params, ConsumerSecret) of
        ok -> verify_signature(Realm, Path, Params, ConsumerSecret);
        Error -> Error
    end.

%%
%% @doc Check that the nonce of an oauth 1.0 request have not been used before.
%%
-spec verify_nonce(string(), string(), params_t(), string()) -> ok | {error, string()}.

verify_nonce(_Realm, _Path, Params, _ConsumerSecret) ->
    {_, Nonce} = lists:keyfind(?NONCE_PARAM, 1, Params),
    case nonce_insert(Nonce) of
        true  -> ok;
        false -> {error, "oauth_nonce has been used"}
    end.

%%
%% @doc Verify the signature of an oauth 1.0 request
%%
-spec verify_signature(string(), string(), params_t(), string()) -> ok | {error, string()}.

verify_signature(Realm, Path, Params, ConsumerSecret) ->
    {_, ConsumerKey} = lists:keyfind(?CONSUMER_KEY_PARAM, 1, Params),
    {value, {_, Signature}, OtherParams} = lists:keytake(?SIGNATURE_PARAM, 1, Params),
    Url = Realm ++ Path,
    Consumer = {ConsumerKey, ConsumerSecret, hmac_sha1},
    case oauth:verify(Signature, "GET", Url, OtherParams, Consumer, "") of
        true  -> ok;
        false -> {error, "oauth_signature invalid"}
    end.

%%
%% @doc Extract the consumer key from the query string parameters
%%
-spec get_consumer_key(params_t()) -> false | string().

get_consumer_key(Params) ->
    case lists:keyfind(?CONSUMER_KEY_PARAM, 1, Params) of
        false -> false;
        {_, Value} -> Value
    end.

%%
%% @doc Check that the required parameters are present with their expected values.
%%
-spec check_params(params_t()) -> ok | {error, string()}.

check_params(Params) ->
    check_params(missing, Params).


% Privates

check_params(missing, Params) ->
    case check_required_params(Params) of
        ok    -> check_params(version, Params);
        Error -> Error
    end;

check_params(version, Params) ->
    case lists:keyfind(?VERSION_PARAM, 1, Params) of
        false      -> check_params(signature, Params);  % unspecified version is fine, assume 1.0
        {_, "1.0"} -> check_params(signature, Params);
        _          -> {error, "oauth_version must be 1.0"}
    end;

check_params(signature, Params) ->
    case lists:keyfind(?SIGNATURE_METHOD_PARAM, 1, Params) of
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
     ?CONSUMER_KEY_PARAM,
     ?SIGNATURE_METHOD_PARAM,
     ?SIGNATURE_PARAM,
     ?TIMESTAMP_PARAM,
     ?NONCE_PARAM
    ].



nonce_insert(Nonce) when is_list(Nonce) ->
    nonce_insert(list_to_binary(Nonce));

nonce_insert(Nonce) when is_binary(Nonce) ->
    ets:insert_new(oauth_nonce, {Nonce}).
