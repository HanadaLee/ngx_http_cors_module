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
--- request
GET /
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
--- request
GET /
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
--- request
GET /
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
--- request
GET /
--- response_headers_absent
Access-Control-Allow-Origin: http://example.org

=== TEST 5: test with the cors_expose_headers
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept;
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
GET /
--- response_headers
Access-Control-Expose-Headers: AAAA, BBB, CCC

=== TEST 6: test without the cors_expose_headers
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept;
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
GET /
--- response_headers_absent
Access-Control-Expose-Headers: AAAA, BBB, CCC

=== TEST 7: test the core_support_credential
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
GET /
--- response_headers
Access-Control-Allow-Credentials: true

=== TEST 8: test the core_support_credential false
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT POST;
cors_allow_headers Accept Bccept;
cors_expose_headers AAAA Expires BBB CCC;

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
GET /
--- response_headers_absent
Access-Control-Allow-Credentials: true

=== TEST 9: test the request method absent
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods GET PUT;
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
POST /
--- response_headers_absent
Access-Control-Allow-Credentials: true

=== TEST 10: test the contain method
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
POST /
--- response_headers
Access-Control-Allow-Credentials: true

=== TEST 11: test the core_method_list unbounded
--- http_config
cors on;
cors_max_age     3600;
cors_allow_origins http://www.foo.com http://example.org http://bar.net;
cors_allow_methods **;
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
POST /
--- response_headers
Access-Control-Allow-Credentials: true
