-module(oauth_utils).

-export([
         init/0, init/1, init/2,

         is_authorized/6,

         get_header_params/1,
         check_params/1,
         get_consumer_key/1,

         verify/5,
         verify_nonce/1,
         verify_signature/5,

         nonce_expire/1
        ]).

-include_lib("stdlib/include/ms_transform.hrl").

% OAuth parameters
-define(CONSUMER_KEY_PARAM, "oauth_consumer_key").
-define(SIGNATURE_METHOD_PARAM, "oauth_signature_method").
-define(SIGNATURE_PARAM, "oauth_signature").
-define(TIMESTAMP_PARAM, "oauth_timestamp").
-define(NONCE_PARAM, "oauth_nonce").
-define(VERSION_PARAM, "oauth_version").

-define(NONCE_RETENTION_PERIOD_SECS, 15*60).  % remember nonce values by default for 15 minutes
-define(NONCE_EXPIRE_INTERVAL_MS, 60000).     % remove expired nonce values by default every minute

-type params_t() :: [{string(), string()}].


%%
%% @doc Initialize nonce storage and cleanup.
%%
%% Call one of init/{0-2} from your application callback module.
%%
-spec init() -> ok.

init() ->
    init(?NONCE_RETENTION_PERIOD_SECS, ?NONCE_EXPIRE_INTERVAL_MS).


%%
%% @doc Initialize nonce storage and cleanup.
%%
%% Call one of init/{0-2} from your application callback module.
%%
-spec init(pos_integer()) -> ok.

init(NonceRetentionPeriodSecs) ->
    init(NonceRetentionPeriodSecs, ?NONCE_EXPIRE_INTERVAL_MS).


%%
%% @doc Initialize nonce storage and cleanup.
%%
%% Call one of init/{0-2} from your application callback module.
%%
-spec init(pos_integer(), pos_integer()) -> ok.

init(NonceRetentionPeriodSecs, NonceExireIntervalMs) ->
    oauth_nonce = ets:new(oauth_nonce, [set, public, named_table]),
    {ok, _} = timer:apply_interval(NonceExireIntervalMs, ?MODULE, nonce_expire, [NonceRetentionPeriodSecs]),
    ok.


%%
%% @doc FIXME
%%
%-spec

is_authorized(Method, Realm, Path, QueryParams, AuthHeader, FindConsumerSecretFun) ->
    Params = QueryParams ++ get_header_params(AuthHeader),
    case check_params(Params) of
        ok -> 
            ConsumerKey = get_consumer_key(Params),
            case FindConsumerSecretFun(ConsumerKey) of
                {ok, ConsumerSecret} -> verify(Method, Realm, Path, Params, ConsumerSecret);
                error                -> {error, "oauth_consumer_key invalid"}
            end;
        Error -> Error
    end.


%%
%% @doc FIXME
%%
%-spec

get_header_params(String) when is_list(String) ->
    Suffix = re:replace(String, "^oauth\\s+", "", [caseless, {return,list}]),
    Params = oauth:header_params_decode(Suffix),
    case lists:keytake("realm", 1, Params) of
        {value, _, OtherParams} -> OtherParams;
        false                   -> Params
    end;
get_header_params(_) -> [].


%%
%% @doc Check that the required parameters are present with their expected values.
%%
-spec check_params(params_t()) -> ok | {error, string()}.

check_params(Params) ->
    check_params(missing, Params).


%%
%% @doc Extract the consumer key from the query string parameters
%%
-spec get_consumer_key(params_t()) -> false | string().

get_consumer_key(Params) ->
    case lists:keyfind(?CONSUMER_KEY_PARAM, 1, Params) of
        false      -> false;
        {_, Value} -> Value
    end.


%%
%% @doc Verify an oauth 1.0 request by checking the nonce and signature.
%%
%% See verify_nonce/1 and verify_signature/5
%%
-spec verify(atom(), string(), string(), params_t(), string()) -> ok | {error, string()}.

verify(Method, Realm, Path, Params, ConsumerSecret) ->
    case verify_nonce(Params) of
        ok    -> verify_signature(Method, Realm, Path, Params, ConsumerSecret);
        Error -> Error
    end.


%%
%% @doc Check that the nonce of an oauth 1.0 request have not been used before.
%%
-spec verify_nonce(params_t()) -> ok | {error, string()}.

verify_nonce(Params) ->
    {_, Nonce} = lists:keyfind(?NONCE_PARAM, 1, Params),
    case nonce_insert(Nonce) of
        true  -> ok;
        false -> {error, "oauth_nonce has been used"}
    end.


%%
%% @doc Verify the signature of an oauth 1.0 request
%%
-spec verify_signature(atom(), string(), string(), params_t(), string()) -> ok | {error, string()}.

verify_signature(Method, Realm, Path, Params, ConsumerSecret) ->
    {_, ConsumerKey} = lists:keyfind(?CONSUMER_KEY_PARAM, 1, Params),
    {value, {_, Signature}, OtherParams} = lists:keytake(?SIGNATURE_PARAM, 1, Params),
    Url = Realm ++ Path,
    Consumer = {ConsumerKey, ConsumerSecret, hmac_sha1},
    case oauth:verify(Signature, atom_to_list(Method), Url, OtherParams, Consumer, "") of
        true  -> ok;
        false -> {error, "oauth_signature invalid"}
    end.


%%
%% Helper funs
%%

check_params(missing, Params) ->
    case check_required_params(Params, required_params()) of
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
        {_, "HMAC-SHA1"} -> ok;
        _                -> {error, "oauth_signature_method must be HMAC-SHA1"}
    end.


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
    ets:insert_new(oauth_nonce, {Nonce, unixtime()}).


nonce_expire(Retention) ->
    Now = unixtime(),
    ets:select_delete(oauth_nonce, ets:fun2ms(fun({_,Timestamp}) when Timestamp < Now-Retention -> true end)).


unixtime() ->
    {Mega, Secs, _} = os:timestamp(),
    Mega*1000000 + Secs.
