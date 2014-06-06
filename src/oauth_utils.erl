-module(oauth_utils).

% Main interface
-export([
         init/0, init/2,
         wellformed_request/2, wellformed_request/4,
         is_authorized/3,
         get_other_params/1,
         get_consumer_key/1
        ]).

% Called by timer module
-export([
         nonce_expire/1
        ]).

-ifdef(TEST).
-compile([export_all]).
-endif.

-include("oauth_utils.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

% OAuth parameters
-define(CONSUMER_KEY_PARAM, "oauth_consumer_key").
-define(SIGNATURE_METHOD_PARAM, "oauth_signature_method").
-define(SIGNATURE_PARAM, "oauth_signature").
-define(TIMESTAMP_PARAM, "oauth_timestamp").
-define(NONCE_PARAM, "oauth_nonce").
-define(VERSION_PARAM, "oauth_version").
-define(TOKEN_PARAM, "oauth_token").

-define(NONCE_RETENTION_PERIOD_SECS, 15*60).  % remember nonce values by default for 15 minutes
-define(NONCE_EXPIRE_INTERVAL_MS, 60000).     % remove expired nonce values by default every minute

-type params_t() :: [{string(), string()}].


%%
%% @doc Initialize nonce storage and cleanup.
%%
%% Call one of init/{0,2} from your application callback module.
%%
-spec init() -> ok.

init() ->
    init(?NONCE_RETENTION_PERIOD_SECS, ?NONCE_EXPIRE_INTERVAL_MS).


%%
%% @doc Initialize nonce storage and cleanup.
%%
%% Call one of init/{0,2} from your application callback module.
%%
-spec init(pos_integer(), pos_integer()) -> ok.

init(NonceRetentionPeriodSecs, NonceExpireIntervalMs) ->
    oauth_nonce = ets:new(oauth_nonce, [set, public, named_table]),
    {ok, _} = timer:apply_interval(NonceExpireIntervalMs, ?MODULE, nonce_expire, [NonceRetentionPeriodSecs]),
    ok.


%%
%% @doc Convenience funs for webmachine and mochiweb that perform parameter checking.
%%
-spec wellformed_request(atom(), any()) -> {ok, #oauth_req{}} | {error, string()}.

wellformed_request(webmachine, ReqData) ->
    Method = wrq:method(ReqData),
    Path = wrq:path(ReqData),
    QueryParams = wrq:req_qs(ReqData),
    AuthHeader = wrq:get_req_header("Authorization", ReqData),
    wellformed_request(Method, Path, QueryParams, AuthHeader);

wellformed_request(mochiweb, Req) ->
    Method = Req:get(method),
    Path = Req:get(path),
    QueryParams = Req:parse_qs(),
    AuthHeader = Req:get_header_value("Authorization"),
    wellformed_request(Method, Path, QueryParams, AuthHeader).


%%
%% @doc Perform parameter checking.
%%
-spec wellformed_request(atom(), string(), params_t(), string()) -> {ok, #oauth_req{}} | {error, string()}.

wellformed_request(Method, Path, QueryParams, AuthHeader) ->
    case parse_auth_header(AuthHeader) of
        {ok, AuthHeaderParams} ->
            Params = QueryParams ++ AuthHeaderParams,
            check_params(#oauth_req{
                            method       = Method,
                            path         = Path,
                            query_params = QueryParams,
                            params       = Params
                           });
        Error -> Error
    end.


%%
%% @doc Performs nonce and signature verification.
%%
-spec is_authorized(string(), string(), #oauth_req{})                               -> ok | {error, string()};
                   (string(), fun((string()) -> {ok,string()}|error), #oauth_req{}) -> ok | {error, string()}.

is_authorized(Realm, ConsumerSecret, Req = #oauth_req{}) when is_list(ConsumerSecret) ->
    case verify_nonce(Req) of
        ok    -> verify_signature(Realm, ConsumerSecret, Req);
        Error -> Error
    end;

is_authorized(Realm, FindConsumerSecretFun, Req = #oauth_req{consumer_key=ConsumerKey}) when is_function(FindConsumerSecretFun) ->
    case FindConsumerSecretFun(ConsumerKey) of
        {ok, ConsumerSecret} -> is_authorized(Realm, ConsumerSecret, Req);
        _                    -> {error, ?CONSUMER_KEY_PARAM " invalid"}
    end.


%%
%% @doc Returns the query string parameters with OAuth parameters removed.
%%
-spec get_other_params(#oauth_req{}) -> params_t().

get_other_params(#oauth_req{query_params=QueryParams}) ->
    OAuthKeys = oauth_keys(),
    lists:filter(fun({K,_}) -> not ordsets:is_element(K, OAuthKeys) end, QueryParams).


%%
%% @doc Returns the OAuth consumer key parameter.
%%
-spec get_consumer_key(#oauth_req{}) -> string().

get_consumer_key(#oauth_req{consumer_key=ConsumerKey}) ->
    ConsumerKey.


%%
%% Helper funs
%%

parse_auth_header(String) when is_list(String) ->
    try
        {match, [{0,N}]} = re:run(String, "^oauth[[:blank:]]+.", [caseless]),  % must begin with oauth
        String2 = re:replace(string:substr(String,N), "(\\r\\n)?[[:blank:]]+", " ", [global, {return,list}]),  % strip linear white space
        Params = oauth:header_params_decode(String2),
        lists:keydelete("realm", 1, Params)
    of
        ParamsExclRealm -> {ok, ParamsExclRealm}
    catch
        _:_ -> {error, "Authorization header malformed"}
    end;
parse_auth_header(_) -> {ok, []}.


check_params(Req = #oauth_req{params=Params}) ->
    try
        Dict = build_oauth_param_dict(Params),
        {ok, Req#oauth_req{
               consumer_key     = get_required_param(?CONSUMER_KEY_PARAM, Dict),
               signature_method = check_signature_method(get_required_param(?SIGNATURE_METHOD_PARAM, Dict)),
               signature        = get_required_param(?SIGNATURE_PARAM, Dict),
               timestamp        = get_required_param(?TIMESTAMP_PARAM, Dict),
               nonce            = get_required_param(?NONCE_PARAM, Dict),
               version          = check_version(get_optional_param(?VERSION_PARAM, Dict, "1.0"))
              }}
    catch
        Reason -> {error, Reason}
    end.


verify_nonce(#oauth_req{nonce=Nonce}) ->
    case nonce_insert(Nonce) of
        true  -> ok;
        false -> {error, ?NONCE_PARAM " has been used"}
    end.


verify_signature(Realm, ConsumerSecret, #oauth_req{method=Method, path=Path, params=Params, consumer_key=ConsumerKey, signature=Signature}) ->
    Url = Realm ++ Path,
    ParamsExclSignature = lists:keydelete(?SIGNATURE_PARAM, 1, Params),
    Consumer = {ConsumerKey, ConsumerSecret, hmac_sha1},
    case oauth:verify(Signature, atom_to_list(Method), Url, ParamsExclSignature, Consumer, "") of
        true  -> ok;
        false -> {error, ?SIGNATURE_PARAM " invalid"}
    end.


oauth_keys() ->
    ordsets:from_list([?CONSUMER_KEY_PARAM,
                       ?SIGNATURE_METHOD_PARAM,
                       ?SIGNATURE_PARAM,
                       ?TIMESTAMP_PARAM,
                       ?NONCE_PARAM,
                       ?VERSION_PARAM,
                       ?TOKEN_PARAM]).


build_oauth_param_dict(Params) ->
    OAuthKeys = oauth_keys(),
    OAuthParams = lists:filter(fun({K,_}) -> ordsets:is_element(K, OAuthKeys) end, Params),
    lists:foldl(fun({K,V}, Acc) -> orddict:append(K, V, Acc) end, [], OAuthParams).


get_required_param(Key, Dict) ->
    case orddict:find(Key, Dict) of
        error       -> throw(Key ++ " must be specified");
        {ok, [Val]} -> Val;
        {ok, _}     -> throw(Key ++ " specified more than once")
    end.


get_optional_param(Key, Dict, Default) ->
    case orddict:find(Key, Dict) of
        error       -> Default;
        {ok, [Val]} -> Val;
        {ok, _}     -> throw(Key ++ " specified more than once")
    end.


check_signature_method(Val="HMAC-SHA1") -> Val;
check_signature_method(_) -> throw(?SIGNATURE_METHOD_PARAM " must be HMAC-SHA1").


check_version(Val="1.0") -> Val;
check_version(_) -> throw(?VERSION_PARAM " must be 1.0").


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
