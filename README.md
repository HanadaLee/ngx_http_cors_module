# ngx_http_cors_module

Support Cross-Origin Resource Sharing (CORS) in Nginx.

## Status

This module is in early development and considered highly experimental. You are encouraged to test it and report any issues you encounter.

Contributions are welcome! If you find this module useful, please consider joining the development.

## Synopsis

```nginx
http {
    cors on;
    cors_max_age           3600;
    cors_allow_origins     **;
    cors_allow_methods     GET HEAD PUT POST;
    cors_allow_headers     **;

    server {
        listen       80;
        server_name  localhost;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
```

## Description

This module implements the [CORS protocol](https://www.w3.org/TR/cors/) (2025-01-13 revision). It handles both simple requests and preflight requests by setting the appropriate `Access-Control-*` response headers.

## Conditional configuration

When `ngx_condition_module` is compiled, every directive in this module may
also be used in `http when`, `server when`, and `location when` blocks.
Different CORS fields are selected independently using their configuration
order. Values defined in the current scope have priority over inherited
fallbacks.

```nginx
condition trusted_origin str_eq $http_origin https://app.example.com;

when trusted_origin {
    cors on;
    cors_allow_origins https://app.example.com;
    cors_allow_methods GET POST OPTIONS;
    cors_allow_headers Authorization;
    cors_allow_credentials on;
}
```

If conditional selection enables credentials together with a `*` origins,
methods, or headers policy, the module logs an error and treats that policy as
`**` for the current request.

## Directives

### cors

**Syntax:** *cors on | off;*
**Default:** *cors off;*
**Context:** *http, server, location, when*

Master switch to enable CORS processing. When enabled, the module intercepts `OPTIONS` requests (preflight) and adds CORS headers to all responses that match the configured policies.

---

### cors_allow_origins

**Syntax:** *cors_allow_origins \* | \*\* | origin ...;*
**Default:** *cors_allow_origins \*;*
**Context:** *http, server, location, when*

Specifies which origins are allowed to access the resource. Supports three modes:

- **`*`** — Wildcard mode. The response always contains `Access-Control-Allow-Origin: *`. Cannot be used together with `cors_allow_credentials on`.
- **`**`** — Reflect mode. Echoes the request's `Origin` header back in the response. If no `Origin` header is present, falls back to `*` when credentials are disabled and omits `Access-Control-Allow-Origin` when credentials are enabled. This is the most common choice for APIs that need to support multiple known origins.
- **Explicit origins** — A space-separated list of allowed origins. Only requests whose `Origin` matches one of the listed origins will receive CORS headers. If the `Origin` does not match, no CORS headers are added and the request proceeds without them.

Origins can be specified as exact strings or, if PCRE support is compiled into Nginx, as regex patterns prefixed with `~`:

```nginx
# Exact origins
cors_allow_origins http://www.foo.com http://new.bar.net http://example.org;

# Regex patterns (requires PCRE)
cors_allow_origins ~^https?://.*\.example\.com$ ~^https?://localhost:\d+$;
```

> **Note:** `*` and `**` cannot be mixed with other origins in the same list.

---

### cors_allow_methods

**Syntax:** *cors_allow_methods \* | \*\* | method ...;*
**Default:** *\*;*
**Context:** *http, server, location, when*

Specifies which HTTP methods are allowed for cross-origin requests. Supports three modes:

- **`*`** — Wildcard mode. The response contains `Access-Control-Allow-Methods: *`. Cannot be used with `cors_allow_credentials on`.
- **`**`** — Unbounded mode. The response contains all standard methods: `GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH`. Use this when you want to explicitly list all methods rather than using a wildcard.
- **Explicit methods** — A space-separated list of allowed HTTP methods.

Method names are case-sensitive and must be uppercase (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, etc.).

```nginx
cors_allow_methods GET POST PUT;
```

---

### cors_allow_headers

**Syntax:** *cors_allow_headers \* | \*\* | header ...;*
**Default:** *\*;*
**Context:** *http, server, location, when*

Specifies which request headers are allowed for cross-origin requests. Supports three modes:

- **`*`** — Wildcard mode. The response contains `Access-Control-Allow-Headers: *`. Cannot be used with `cors_allow_credentials on`.
- **`**`** — Reflect mode. Echoes the request's `Access-Control-Request-Headers` value back in the response. If no such header is present, falls back to `*` when credentials are disabled and omits `Access-Control-Allow-Headers` when credentials are enabled.
- **Explicit headers** — A space-separated list of allowed header field names.

The following safelisted headers are always allowed and will be silently skipped if you include them in the configuration: `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`, `Range`.

```nginx
cors_allow_headers X-Custom-Header Authorization Content-Type;
```

---

### cors_expose_headers

**Syntax:** *cors_expose_headers header ...;*
**Default:** *—*
**Context:** *http, server, location, when*

Specifies which response headers are safe to expose to the browser via `Access-Control-Expose-Headers`. By default, browsers only expose a limited set of response headers (the safelisted response headers: `Cache-Control`, `Content-Language`, `Content-Length`, `Content-Type`, `Expires`, `Last-Modified`, `Pragma`). Use this directive to expose additional headers.

Safelisted response headers included in the list are silently skipped.

```nginx
cors_expose_headers X-Total-Count X-Request-Id;
```

---

### cors_max_age

**Syntax:** *cors_max_age time;*
**Default:** *—*
**Context:** *http, server, location, when*

Specifies how long (in seconds) the browser is allowed to cache the preflight response via `Access-Control-Max-Age`. Common values: `3600` (1 hour), `86400` (1 day). When set to `0` or not configured, the header is omitted.

```nginx
cors_max_age 3600;
```

---

### cors_allow_credentials

**Syntax:** *cors_allow_credentials on | off;*
**Default:** *cors_allow_credentials off;*
**Context:** *http, server, location, when*

Enables `Access-Control-Allow-Credentials: true`, allowing requests to include credentials (cookies, HTTP authentication, client certificates).

**Important:** When credentials are enabled, wildcard `*` cannot be used for `cors_allow_origins`, `cors_allow_methods`, or `cors_allow_headers`. Use `**` or explicit values instead. Without `ngx_condition_module`, Nginx refuses to start if this rule is violated. With conditional configuration, a conflict selected at request time is logged and the affected `*` policy is treated as `**` for that request.

```nginx
cors_allow_credentials on;
cors_allow_origins https://app.example.com;
```

---

### cors_preflight_status

**Syntax:** *cors_preflight_status 200 | 204;*
**Default:** *cors_preflight_status 204;*
**Context:** *http, server, location, when*

Specifies the HTTP status code returned for preflight (`OPTIONS`) requests. Only `200` and `204` are valid values.

```nginx
cors_preflight_status 204;
```

## Configuration Notes

### Credential + Wildcard Restriction

The CORS specification prohibits using wildcard CORS response fields together
with credentials. Without `ngx_condition_module`, this module enforces the
restriction at configuration time:

```nginx
# This will cause a configuration error:
cors_allow_credentials on;
cors_allow_origins *;       # ERROR
cors_allow_methods *;       # ERROR
cors_allow_headers *;       # ERROR

# Use explicit origins or ** instead:
cors_allow_credentials on;
cors_allow_origins **;              # OK — echoes request origin
cors_allow_methods GET POST;        # OK — explicit list
cors_allow_headers Authorization;   # OK — explicit list
```

With conditional configuration, the final values are selected at request time.
If credentials and a `*` policy are selected together, the module logs an error
and treats only the conflicting policy as `**` for that request. Origins and
headers are reflected from the request, while methods use the full standard
method list.

### Preflight Request Handling

When a browser needs to make a cross-origin request that is not a "simple request", it first sends an `OPTIONS` preflight request. This module automatically intercepts preflight requests and returns the configured status code with appropriate CORS headers. The actual request processing is handled by the normal Nginx request flow with CORS headers added to the response.

## Installation

1. Download the module from [GitHub](https://github.com/HanadaLee/ngx_http_cors_module).

2. Download the Nginx source (e.g., version 1.27.1) from [nginx.org](https://nginx.org/) and build with this module:

   ```sh
   wget http://nginx.org/download/nginx-1.27.1.tar.gz
   tar -xzvf nginx-1.27.1.tar.gz
   cd nginx-1.27.1/

   ./configure --add-module=/path/to/ngx_http_cors_module

   make
   make install
   ```

## Compatibility

Tested with Nginx 1.27.1.

## Known Issues

Under active development — see [GitHub Issues](https://github.com/HanadaLee/ngx_http_cors_module/issues).

## Changelog

### v1.0

- Refactored module implementation.

### v0.1

- First release.

## Authors

- Weibin Yao (姚伟斌) — yaoweibin AT gmail DOT com
- Hanada — im@hanada.info

## License

This module is licensed under the BSD license.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
