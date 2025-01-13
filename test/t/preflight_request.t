#
#===============================================================================
#
#         FILE:  sample.t
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the first normal request
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins **;
cors_allow_methods **;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Origin: http://example.org

=== TEST 2: turn the module off
--- http_config
cors off;
cors_max_age     3600;
cors_allow_origins **;
cors_allow_methods **;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
--- request
OPTIONS /
--- response_headers_absent
Access-Control-Allow-Origin: http://example.org

=== TEST 3: test the cors_allow_origins succ
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods **;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Origin: http://example.org

=== TEST 4: test the cors_allow_origins fail
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example1.org http://bar.net;
cors_allow_methods **;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
--- request
OPTIONS /
--- response_headers_absent
Access-Control-Allow-Origin: http://example.org

=== TEST 5: test the cors_allow_methods succ
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Origin: http://example.org

=== TEST 6: test the cors_allow_methods fail 1 
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
--- request
OPTIONS /
--- response_headers_absent
Access-Control-Allow-Origin: http://example.org

=== TEST 7: test the cors_allow_methods fail 2 
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET POST;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
--- request
OPTIONS /
--- response_headers_absent
Access-Control-Allow-Origin: http://example.org

=== TEST 8: test the cors_allow_headers succ
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept Bad;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept, Bad
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Headers: Accept, Bccept, Bad

=== TEST 9: test the cors_allow_headers without the Rquest-Headers 
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept Bad;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
--- request
OPTIONS /
--- response_headers_absent
Access-Control-Allow-Origin: http://example.org

=== TEST 10: test the cors_allow_headers mismatch with the list of headers  
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Bccept Foo Bar;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Accept, Good
--- request
OPTIONS /
--- response_headers_absent
Access-Control-Allow-Origin: http://example.org

=== TEST 11: test the cors_allow_headers not simple header
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Headers: Accept, Bccept

=== TEST 12: test the cors_allow_credentials
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Credentials: true

=== TEST 13: test the core_max_age
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept
--- request
OPTIONS /
--- response_headers
Access-Control-Max-Age: 3600

=== TEST 14: test the preflight response body
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept
--- request
OPTIONS /
--- response_body: Foo Bar!

=== TEST 14: test the preflight default response body
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept
--- request
OPTIONS /
--- response_body:

=== TEST 15: test the preflight response content-type
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;
cors_preflight_response_type "text/plain; charset=UTF-8";

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept
--- request
OPTIONS /
--- response_headers
Content-type: text/plain; charset=UTF-8

=== TEST 16: test the preflight default response content-type
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Bccept
--- request
OPTIONS /
--- response_headers
Content-type: text/plain

=== TEST 17: test the cors_allow_headers match the header
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Bccept Foo Bar;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Accept, Good, foo
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Headers: Bccept, Foo, Bar

=== TEST 18: test the cors_allow_headers unbounded
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers **;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Authorization,Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control, access-control-allow-credentials,access-control-allow-methods,access-control-allow-origin,access-control-max-age, Bad, foo, nice
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Headers: Authorization,Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control, access-control-allow-credentials,access-control-allow-methods,access-control-allow-origin,access-control-max-age, Bad, foo, nice

=== TEST 19: test the cors_allow_headers match the header
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Bccept Foo Bar;
cors_expose_headers AAAA Expires BBB CCC;
cors_allow_credentials on;

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Origin: http://example.org
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Authorization,Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control, access-control-allow-credentials,access-control-allow-methods,access-control-allow-origin,access-control-max-age, Bad, foo, nice
--- request
OPTIONS /
--- response_headers
Access-Control-Allow-Headers: Bccept, Foo, Bar

