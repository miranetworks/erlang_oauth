% OAuth request record
-record(oauth_req, {
          method,
          path,
          query_params,  % query string params
          params,        % query string params ++ auth header params

          consumer_key,
          signature_method,
          signature,
          timestamp,
          nonce,
          version
         }).
