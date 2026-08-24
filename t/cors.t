#!/usr/bin/perl

# Tests for ngx_http_cors_module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite pcre ngx_condition_module
	ngx_http_cors_module/)->plan(60);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        default_type text/plain;

        condition trusted str_eq $arg_mode trusted;

        location = /exact {
            cors on;
            cors_allow_origins https://allowed.example;
            cors_allow_methods GET POST;
            cors_allow_headers X-Token Content-Type;
            cors_expose_headers X-Trace Content-Length;
            cors_max_age 600;
            cors_allow_credentials on;
            return 200 exact;
        }

        location = /regex {
            cors on;
            cors_allow_origins ~^https://[a-z]+\.example$;
            cors_allow_methods GET;
            cors_allow_headers X-Token;
            return 200 regex;
        }

        location = /off {
            cors off;
            cors_allow_origins *;
            return 200 off;
        }

        location = /status {
            cors on;
            cors_allow_origins https://allowed.example;
            cors_allow_methods POST;
            cors_allow_headers X-Token;
            cors_preflight_status 200;
            return 405;
        }

        location = /wildcard {
            cors on;
            cors_allow_origins *;
            cors_allow_methods *;
            cors_allow_headers *;
            return 200 wildcard;
        }

        location = /reflect {
            cors on;
            cors_allow_origins **;
            cors_allow_methods **;
            cors_allow_headers **;
            cors_allow_credentials on;
            return 200 reflect;
        }

        location = /conditional {
            when trusted {
                cors on;
                cors_allow_origins https://trusted.example;
                cors_allow_methods POST;
                cors_allow_headers X-Trusted;
                cors_expose_headers X-Trusted-Response;
                cors_max_age 900;
                cors_allow_credentials on;
                cors_preflight_status 200;
            }

            cors off;
            cors_allow_origins https://fallback.example;
            cors_allow_methods GET;
            cors_allow_headers X-Fallback;
            cors_expose_headers X-Fallback-Response;
            cors_max_age 30;
            cors_allow_credentials off;
            cors_preflight_status 204;

            return 200 conditional;
        }

        location = /order {
            cors on;
            cors_allow_origins https://first.example;

            when trusted {
                cors off;
                cors_allow_origins https://second.example;
            }

            return 200 order;
        }
    }
}

EOF

$t->run();

###############################################################################

my $response = request('GET', '/exact',
	'Origin: https://allowed.example');

like($response, qr/^HTTP\/1\.1 200 /, 'exact origin request succeeds');
like($response, qr/^Access-Control-Allow-Origin: https:\/\/allowed\.example\x0d$/m,
	'exact origin is reflected');
like($response, qr/^Vary: Origin\x0d$/m,
	'exact origin response varies by origin');
like($response, qr/^Access-Control-Allow-Credentials: true\x0d$/m,
	'credentials are enabled');
like($response, qr/^Access-Control-Allow-Methods: GET, POST\x0d$/m,
	'explicit methods are emitted');
like($response, qr/^Access-Control-Allow-Headers: X-Token\x0d$/m,
	'safelisted request headers are omitted from configured headers');
like($response, qr/^Access-Control-Expose-Headers: X-Trace\x0d$/m,
	'safelisted response headers are omitted from exposed headers');
like($response, qr/^Access-Control-Max-Age: 600\x0d$/m,
	'max age is emitted');

$response = request('GET', '/exact', 'Origin: https://denied.example');
like($response, qr/^HTTP\/1\.1 200 /, 'denied actual request still reaches content');
unlike($response, qr/^Access-Control-/m,
	'denied actual request has no CORS headers');

$response = request('GET', '/regex', 'Origin: https://api.example');
like($response, qr/^HTTP\/1\.1 200 /, 'regex origin request succeeds');
like($response, qr/^Access-Control-Allow-Origin: https:\/\/api\.example\x0d$/m,
	'regex origin is accepted');
like($response, qr/^Vary: Origin\x0d$/m,
	'regex origin response varies by origin');

$response = request('GET', '/regex', 'Origin: https://api.invalid');
like($response, qr/^HTTP\/1\.1 200 /, 'regex mismatch still reaches content');
unlike($response, qr/^Access-Control-/m, 'regex mismatch has no CORS headers');

$response = request('GET', '/off', 'Origin: https://allowed.example');
like($response, qr/^HTTP\/1\.1 200 /, 'disabled location serves content');
unlike($response, qr/^Access-Control-/m, 'cors off suppresses CORS headers');

$response = request('OPTIONS', '/exact',
	'Origin: https://allowed.example',
	'Access-Control-Request-Method: POST',
	'Access-Control-Request-Headers: Content-Type, X-Token');

like($response, qr/^HTTP\/1\.1 204 /, 'valid preflight uses default status');
is(response_body($response), '', 'valid preflight has no body');
like($response, qr/^Access-Control-Allow-Origin: https:\/\/allowed\.example\x0d$/m,
	'valid preflight allows origin');
like($response, qr/^Access-Control-Allow-Methods: GET, POST\x0d$/m,
	'valid preflight returns configured methods');
like($response, qr/^Access-Control-Allow-Headers: X-Token\x0d$/m,
	'valid preflight returns configured non-safelisted headers');
like($response, qr/^Access-Control-Allow-Credentials: true\x0d$/m,
	'valid preflight allows credentials');
like($response, qr/^Access-Control-Expose-Headers: X-Trace\x0d$/m,
	'valid preflight returns exposed headers');
like($response, qr/^Access-Control-Max-Age: 600\x0d$/m,
	'valid preflight returns max age');
like($response, qr/^Vary: Origin\x0d$/m,
	'valid preflight varies by origin');

$response = request('OPTIONS', '/exact',
	'Origin: https://denied.example',
	'Access-Control-Request-Method: POST');
like($response, qr/^HTTP\/1\.1 403 /, 'preflight rejects denied origin');
unlike($response, qr/^Access-Control-Allow-Origin:/m,
	'denied origin is not returned');

$response = request('OPTIONS', '/exact',
	'Origin: https://allowed.example',
	'Access-Control-Request-Method: DELETE');
like($response, qr/^HTTP\/1\.1 403 /, 'preflight rejects denied method');
unlike($response, qr/^Access-Control-Allow-Origin:/m,
	'denied method does not return CORS fields');

$response = request('OPTIONS', '/exact',
	'Origin: https://allowed.example',
	'Access-Control-Request-Method: POST',
	'Access-Control-Request-Headers: X-Denied');
like($response, qr/^HTTP\/1\.1 403 /, 'preflight rejects denied header');
unlike($response, qr/^Access-Control-Allow-Origin:/m,
	'denied header does not return CORS fields');

$response = request('OPTIONS', '/exact',
	'Origin: https://allowed.example');
like($response, qr/^HTTP\/1\.1 403 /,
	'preflight rejects a missing requested method');
unlike($response, qr/^Access-Control-Allow-Origin:/m,
	'missing method does not return CORS fields');

$response = request('OPTIONS', '/status',
	'Origin: https://allowed.example',
	'Access-Control-Request-Method: POST',
	'Access-Control-Request-Headers: X-Token');
like($response, qr/^HTTP\/1\.1 200 /, 'configured preflight status is used');
is(response_body($response), '', '200 preflight has no body');
like($response, qr/^Access-Control-Allow-Origin: https:\/\/allowed\.example\x0d$/m,
	'200 preflight includes CORS headers');

$response = request('OPTIONS', '/wildcard',
	'Origin: https://any.example',
	'Access-Control-Request-Method: PATCH',
	'Access-Control-Request-Headers: X-Any');
like($response, qr/^Access-Control-Allow-Origin: \*\x0d$/m,
	'wildcard origin emits an asterisk');
like($response, qr/^Access-Control-Allow-Methods: \*\x0d$/m,
	'wildcard methods emit an asterisk');
like($response, qr/^Access-Control-Allow-Headers: \*\x0d$/m,
	'wildcard headers emit an asterisk');
unlike($response, qr/^Vary:/m, 'wildcard origin does not add Vary');
unlike($response, qr/^Access-Control-Allow-Credentials:/m,
	'wildcard response does not allow credentials');

$response = request('OPTIONS', '/reflect',
	'Origin: https://reflected.example',
	'Access-Control-Request-Method: PATCH',
	'Access-Control-Request-Headers: X-One, X-Two');
like($response, qr/^HTTP\/1\.1 204 /, 'reflect preflight succeeds');
like($response,
	qr/^Access-Control-Allow-Origin: https:\/\/reflected\.example\x0d$/m,
	'reflect mode echoes origin');
like($response,
	qr/^Access-Control-Allow-Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH\x0d$/m,
	'unbounded methods emit all standard methods');
like($response, qr/^Access-Control-Allow-Headers: X-One, X-Two\x0d$/m,
	'reflect mode echoes requested headers');
like($response, qr/^Vary: Origin\x0d$/m,
	'reflected origin response varies by origin');
like($response, qr/^Access-Control-Allow-Credentials: true\x0d$/m,
	'reflect mode supports credentials');

$response = request('OPTIONS', '/conditional?mode=trusted',
	'Origin: https://trusted.example',
	'Access-Control-Request-Method: POST',
	'Access-Control-Request-Headers: X-Trusted');
like($response, qr/^HTTP\/1\.1 200 /,
	'matching condition selects preflight status');
is(response_body($response), '', 'conditional preflight has no body');
like($response, qr/^Access-Control-Allow-Origin: https:\/\/trusted\.example\x0d$/m,
	'matching condition selects origin');
like($response, qr/^Access-Control-Allow-Methods: POST\x0d$/m,
	'matching condition selects methods');
like($response, qr/^Access-Control-Allow-Headers: X-Trusted\x0d$/m,
	'matching condition selects headers');
like($response,
	qr/^Access-Control-Expose-Headers: X-Trusted-Response\x0d$/m,
	'matching condition selects exposed headers');
like($response, qr/^Access-Control-Allow-Credentials: true\x0d$/m,
	'matching condition selects credentials');
like($response, qr/^Access-Control-Max-Age: 900\x0d$/m,
	'matching condition selects max age');

$response = request('GET', '/conditional?mode=other',
	'Origin: https://fallback.example');
like($response, qr/^HTTP\/1\.1 200 /, 'condition miss reaches content');
unlike($response, qr/^Access-Control-/m,
	'condition miss selects unconditional disabled fallback');

$response = request('GET', '/order?mode=trusted',
	'Origin: https://first.example');
like($response, qr/^Access-Control-Allow-Origin: https:\/\/first\.example\x0d$/m,
	'first unconditional value wins over a later matching condition');
unlike($response, qr/^Access-Control-Allow-Origin: https:\/\/second\.example/m,
	'later condition does not take priority');

###############################################################################

sub request {
	my ($method, $uri, @headers) = @_;
	my $headers = join("\n", @headers);

	$headers .= "\n" if length $headers;

	return http(<<EOF);
$method $uri HTTP/1.1
Host: localhost
${headers}Connection: close

EOF
}


sub response_body {
	my ($response) = @_;

	$response =~ s/^.*?\x0d\x0a\x0d\x0a//s;
	return $response;
}

###############################################################################
