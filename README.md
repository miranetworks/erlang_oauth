erlang_oauth
============

This is an example server side implementation of the `oauth 1.0` signature mechanism as defined in [Using OAuth for Consumer Requests](http://oauth.googlecode.com/svn/spec/ext/consumer_request/1.0/drafts/2/spec.html).

It also provides a utility module `oauth_utils.erl` for easy integration in other applications.


Code examples
=============

Python 2.7
----------
Using [oauthlib](https://github.com/idan/oauthlib):

```python
import oauthlib.oauth1
import urllib2

consumer_key = 'key'
consumer_secret = 'secret'
url = 'http://host:port/path?foo=bar'

# Sign the request
request = oauthlib.oauth1.Client(consumer_key,
                                 client_secret=consumer_secret,
                                 signature_type=oauthlib.oauth1.SIGNATURE_TYPE_QUERY)
signed_url, headers, body = request.sign(url)

# Hit the server
print urllib2.urlopen(signed_url).read()
```

Perl
----
Using [Net::OAuth](https://github.com/keeth/Net-OAuth):

```perl
use Net::OAuth;
use LWP::Simple;

my $consumer_key = 'key';
my $consumer_secret = 'secret';
my $url = 'http://host:port/path?foo=bar';

# Sign the request
my $request = Net::OAuth->request('consumer')->new(
    consumer_key => $consumer_key,
    consumer_secret => $consumer_secret,
    request_url => $url,
    request_method => 'GET',
    signature_method => 'HMAC-SHA1',
    timestamp => time,
    nonce => int(rand(2 ** 32)));
$request->sign;
my $signed_url = $request->to_url;

# Hit the server
print get($signed_url);
```
