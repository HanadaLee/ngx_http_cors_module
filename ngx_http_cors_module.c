
/* All the cross origin resource sharing request processing steps
 * follow this RFC:
 *
 * http://www.w3.org/TR/cors/
 *
 * Author: Weibin Yao
 * Email: yaoweibin@gmail.com
 * Refactored by Hanada
 * Email: im@hanada.info
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_CONDITION)
#include <ngx_http_condition_module.h>
#endif


typedef struct {
    u_char                    *name;
    uint32_t                   method;
} ngx_http_cors_method_name_t;


typedef struct ngx_http_cors_val_s {
    ngx_uint_t                 hash;
    ngx_str_t                  value;
} ngx_http_cors_val_t;


#if (NGX_CONDITION)

typedef struct {
    ngx_array_t               *allow_origins;      /* ngx_http_cors_val_t */
#if (NGX_PCRE)
    ngx_array_t               *allow_origins_regex; /* ngx_regex_elt_t */
#endif
    ngx_int_t                  allow_origins_mode;
    ngx_condition_expr_id_t    expr_id;
} ngx_http_cors_allow_origins_ctx_t;


typedef struct {
    ngx_array_t               *allow_methods;       /* ngx_http_cors_val_t */
    ngx_int_t                  allow_methods_mode;
    ngx_condition_expr_id_t    expr_id;
} ngx_http_cors_allow_methods_ctx_t;


typedef struct {
    ngx_array_t               *allow_headers;       /* ngx_http_cors_val_t */
    ngx_int_t                  allow_headers_mode;
    ngx_condition_expr_id_t    expr_id;
} ngx_http_cors_allow_headers_ctx_t;


typedef struct {
    ngx_array_t               *expose_headers;      /* ngx_http_cors_val_t */
    ngx_condition_expr_id_t    expr_id;
} ngx_http_cors_expose_headers_ctx_t;

#endif /* NGX_CONDITION */


typedef struct {
#if (NGX_CONDITION)
    /* custom conditional contexts */
    ngx_array_t               *allow_origins;
    ngx_array_t               *allow_methods;
    ngx_array_t               *allow_headers;
    ngx_array_t               *expose_headers;

    /* ngx_conf_condition_*_ctx_t */
    ngx_array_t               *enable;
    ngx_array_t               *allow_credentials;
    ngx_array_t               *preflight_status;
    ngx_array_t               *max_age;
#else
    ngx_array_t               *allow_origins;
#if (NGX_PCRE)
    ngx_array_t               *allow_origins_regex;
#endif
    ngx_array_t               *allow_methods;
    ngx_array_t               *allow_headers;
    ngx_array_t               *expose_headers;
    ngx_flag_t                 enable;
    ngx_flag_t                 allow_credentials;
    ngx_int_t                  allow_origins_mode;
    ngx_int_t                  allow_methods_mode;
    ngx_int_t                  allow_headers_mode;
    ngx_uint_t                 preflight_status;
    time_t                     max_age;
#endif
} ngx_http_cors_loc_conf_t;


static ngx_conf_enum_t  ngx_http_cors_preflight_statuses[] = {
    { ngx_string("200"), NGX_HTTP_OK },
    { ngx_string("204"), NGX_HTTP_NO_CONTENT },
    { ngx_null_string, 0 }
};


static ngx_int_t ngx_http_cors_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cors_search_list(ngx_array_t *arr,
        ngx_str_t *name, ngx_flag_t case_insensitive);
static ngx_uint_t ngx_http_cors_get_method(ngx_str_t *method);
static ngx_table_elt_t *ngx_http_cors_search_header(
        ngx_list_t *list, ngx_str_t *name);
static ngx_int_t ngx_http_cors_add_header(ngx_list_t *list,
        ngx_str_t *key, ngx_str_t *value);
static ngx_int_t ngx_http_cors_set_header(ngx_list_t *list,
        ngx_str_t *key, ngx_str_t *value);
static ngx_int_t ngx_http_cors_search_string(ngx_str_t *string_array,
        ngx_str_t *name, ngx_flag_t case_insensitive);
static ngx_str_t *ngx_http_cors_concatenate_list_value(
        ngx_http_request_t *r, ngx_array_t *arr);
static ngx_array_t *ngx_http_cors_split_string(ngx_str_t *str,
        u_char separator, ngx_array_t *arr);

static ngx_int_t ngx_http_cors_header_filter(ngx_http_request_t *r);

static void *ngx_http_cors_create_conf(ngx_conf_t *cf);
static char *ngx_http_cors_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_cors_init(ngx_conf_t *cf);

#if (NGX_PCRE)
static ngx_int_t ngx_http_add_allow_origin_regex(ngx_conf_t *cf,
    ngx_array_t *regex_array, ngx_str_t *name);
#endif
static ngx_int_t ngx_http_add_allow_origin(ngx_conf_t *cf,
    ngx_array_t *origins, ngx_str_t *value);
static char *ngx_http_cors_allow_origins(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_allow_methods(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_allow_headers(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_expose_headers(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

#if (NGX_CONDITION)
static ngx_int_t ngx_http_cors_merge_conditional_allow_origins(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev);
static ngx_int_t ngx_http_cors_merge_conditional_allow_methods(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev);
static ngx_int_t ngx_http_cors_merge_conditional_allow_headers(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev);
static ngx_int_t ngx_http_cors_merge_conditional_expose_headers(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev);
#endif


static ngx_command_t  ngx_http_cors_commands[] = {

    { ngx_string("cors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_FLAG,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, enable),
      NULL },

    { ngx_string("cors_allow_origins"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_1MORE,
      ngx_http_cors_allow_origins,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_allow_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_1MORE,
      ngx_http_cors_allow_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_allow_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_1MORE,
      ngx_http_cors_allow_headers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_expose_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_1MORE,
      ngx_http_cors_expose_headers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_max_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_sec_slot,
#else
      ngx_conf_set_sec_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, max_age),
      NULL },

    { ngx_string("cors_allow_credentials"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_FLAG,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, allow_credentials),
      NULL },

    { ngx_string("cors_preflight_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
      |NGX_HTTP_LOC_WHEN_CONF
#endif
      |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_enum_slot,
#else
      ngx_conf_set_enum_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, preflight_status),
      &ngx_http_cors_preflight_statuses },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_cors_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_cors_init,                         /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server conf */
    NULL,                                       /* merge server conf */

    ngx_http_cors_create_conf,                  /* create location conf */
    ngx_http_cors_merge_conf                    /* merge location conf */
};


ngx_module_t  ngx_http_cors_module = {
    NGX_MODULE_V1,
    &ngx_http_cors_module_ctx,                   /* module context */
    ngx_http_cors_commands,                      /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_str_t ngx_http_cors_request_origin_header = ngx_string("Origin");
static ngx_str_t ngx_http_cors_request_method_header =
    ngx_string("Access-Control-Request-Method");
static ngx_str_t ngx_http_cors_request_headers_header =
    ngx_string("Access-Control-Request-Headers");

static ngx_str_t ngx_http_cors_response_origin_header =
    ngx_string("Access-Control-Allow-Origin");
static ngx_str_t ngx_http_cors_response_credential_header =
    ngx_string("Access-Control-Allow-Credentials");
static ngx_str_t ngx_http_cors_response_max_age_header =
    ngx_string("Access-Control-Max-Age");
static ngx_str_t ngx_http_cors_response_method_header =
    ngx_string("Access-Control-Allow-Methods");
static ngx_str_t ngx_http_cors_response_headers_header =
    ngx_string("Access-Control-Allow-Headers");
static ngx_str_t ngx_http_cors_response_expose_headers_header =
    ngx_string("Access-Control-Expose-Headers");
static ngx_str_t ngx_http_cors_response_vary_header = ngx_string("Vary");

static ngx_str_t ngx_http_cors_response_value_true = ngx_string("true");
static ngx_str_t ngx_http_cors_response_value_wildcard = ngx_string("*");
static ngx_str_t ngx_http_cors_response_methods_unbounded =
    ngx_string("GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH");

#if 0
/* case-sensitive */
static ngx_str_t ngx_http_cors_simple_methods[] = {
    ngx_string("GET"),
    ngx_string("HEAD"),
    ngx_string("POST"),
    { 0, NULL }
};
#endif

/* case-insensitive */
static ngx_str_t ngx_http_cors_safelisted_request_headers[] = {
    ngx_string("Accept"),
    ngx_string("Accept-Language"),
    ngx_string("Content-Language"),
    ngx_string("Content-Type"),
    ngx_string("Range"),
    { 0, NULL }
};

#if 0
/* case-insensitive */
static ngx_str_t ngx_http_cors_simple_types[] = {
    ngx_string("application/x-www-form-urlencoded"),
    ngx_string("multipart/form-data"),
    ngx_string("text/plain"),
    { 0, NULL }
};
#endif

/* case-insensitive */
static ngx_str_t ngx_http_cors_safelisted_response_headers[] = {
    ngx_string("Cache-Control"),
    ngx_string("Content-Language"),
    ngx_string("Content-Length"),
    ngx_string("Content-Type"),
    ngx_string("Expires"),
    ngx_string("Last-Modified"),
    ngx_string("Pragma"),
    { 0, NULL }
};


static ngx_http_cors_method_name_t  ngx_http_cors_methods_names[] = {
    { (u_char *) "GET",       (uint32_t) NGX_HTTP_GET },
    { (u_char *) "HEAD",      (uint32_t) NGX_HTTP_HEAD },
    { (u_char *) "POST",      (uint32_t) NGX_HTTP_POST },
    { (u_char *) "PUT",       (uint32_t) NGX_HTTP_PUT },
    { (u_char *) "DELETE",    (uint32_t) NGX_HTTP_DELETE },
    { (u_char *) "MKCOL",     (uint32_t) NGX_HTTP_MKCOL },
    { (u_char *) "COPY",      (uint32_t) NGX_HTTP_COPY },
    { (u_char *) "MOVE",      (uint32_t) NGX_HTTP_MOVE },
    { (u_char *) "OPTIONS",   (uint32_t) NGX_HTTP_OPTIONS },
    { (u_char *) "PROPFIND" , (uint32_t) NGX_HTTP_PROPFIND },
    { (u_char *) "PROPPATCH", (uint32_t) NGX_HTTP_PROPPATCH },
    { (u_char *) "LOCK",      (uint32_t) NGX_HTTP_LOCK },
    { (u_char *) "UNLOCK",    (uint32_t) NGX_HTTP_UNLOCK },
    { (u_char *) "PATCH",     (uint32_t) NGX_HTTP_PATCH },
    { (u_char *) "TRACE",     (uint32_t) NGX_HTTP_TRACE },
    { (u_char *) "CONNECT",   (uint32_t) NGX_HTTP_CONNECT },
    { NULL, 0 }
};


/* For Preflight Request */
static ngx_int_t
ngx_http_cors_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_cors_loc_conf_t   *colcf;
#if (NGX_CONDITION)
    ngx_flag_t                  enable;
#endif

    colcf = ngx_http_get_module_loc_conf(r, ngx_http_cors_module);

#if (NGX_CONDITION)
    enable = ngx_http_get_conditional_flag_value(r, colcf->enable);
    if (!enable) {
        return NGX_DECLINED;
    }
#else
    if (!colcf->enable) {
        return NGX_DECLINED;
    }
#endif

    if (r->method != NGX_HTTP_OPTIONS) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cors rewrite handler \"%V\"", &r->uri);

#if (NGX_CONDITION)
    r->headers_out.status =
        ngx_http_get_conditional_enum_value(r, colcf->preflight_status);
#else
    r->headers_out.status = colcf->preflight_status;
#endif
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    ngx_http_finalize_request(r, ngx_http_send_header(r));
    return NGX_OK;
}


static ngx_int_t
ngx_http_cors_header_filter(ngx_http_request_t *r)
{
    u_char                            *last;
    ngx_str_t                         *allow_origin;
    ngx_str_t                         *allow_methods;
    ngx_str_t                         *allow_headers;
    ngx_str_t                          str_max_age;
    ngx_str_t                         *fnames, *str_tmp;
    ngx_uint_t                         method, i;
    ngx_array_t                       *field_names;   /* array of ngx_str_t */
    ngx_table_elt_t                   *h;
    ngx_uint_t                         preflight;
    ngx_http_cors_loc_conf_t          *colcf;

#if (NGX_PCRE)
    ngx_int_t                          rc;
#endif

    ngx_flag_t                         enable;
    ngx_flag_t                         allow_credentials;
    time_t                             max_age;
    ngx_array_t                       *allow_origins_arr;
#if (NGX_PCRE)
    ngx_array_t                       *allow_origins_regex_arr;
#endif
    ngx_array_t                       *allow_methods_arr;
    ngx_array_t                       *allow_headers_arr;
    ngx_array_t                       *expose_headers_arr;

    ngx_int_t                          allow_origins_mode;
    ngx_int_t                          allow_methods_mode;
    ngx_int_t                          allow_headers_mode;

#if (NGX_CONDITION)
    ngx_http_cors_allow_origins_ctx_t  *ao_ctx;
    ngx_http_cors_allow_methods_ctx_t  *am_ctx;
    ngx_http_cors_allow_headers_ctx_t  *ah_ctx;
    ngx_http_cors_expose_headers_ctx_t *eh_ctx;
#endif

    colcf = ngx_http_get_module_loc_conf(r, ngx_http_cors_module);

#if (NGX_CONDITION)
    enable = ngx_http_get_conditional_flag_value(r, colcf->enable);
    allow_credentials = ngx_http_get_conditional_flag_value(r,
                            colcf->allow_credentials);
    max_age = ngx_http_get_conditional_sec_value(r, colcf->max_age);

    ao_ctx = ngx_conf_get_conditional_ctx(r, colcf->allow_origins,
                 sizeof(ngx_http_cors_allow_origins_ctx_t),
                 offsetof(ngx_http_cors_allow_origins_ctx_t, expr_id),
                 ngx_http_condition_eval_expr);

    am_ctx = ngx_conf_get_conditional_ctx(r, colcf->allow_methods,
                 sizeof(ngx_http_cors_allow_methods_ctx_t),
                 offsetof(ngx_http_cors_allow_methods_ctx_t, expr_id),
                 ngx_http_condition_eval_expr);

    ah_ctx = ngx_conf_get_conditional_ctx(r, colcf->allow_headers,
                 sizeof(ngx_http_cors_allow_headers_ctx_t),
                 offsetof(ngx_http_cors_allow_headers_ctx_t, expr_id),
                 ngx_http_condition_eval_expr);

    eh_ctx = ngx_conf_get_conditional_ctx(r, colcf->expose_headers,
                 sizeof(ngx_http_cors_expose_headers_ctx_t),
                 offsetof(ngx_http_cors_expose_headers_ctx_t, expr_id),
                 ngx_http_condition_eval_expr);

    if (ao_ctx != NULL) {
        allow_origins_arr = ao_ctx->allow_origins;
#if (NGX_PCRE)
        allow_origins_regex_arr = ao_ctx->allow_origins_regex;
#endif
        allow_origins_mode = ao_ctx->allow_origins_mode;

    } else {
        allow_origins_arr = NULL;
#if (NGX_PCRE)
        allow_origins_regex_arr = NULL;
#endif
        allow_origins_mode = 1; /* default: wildcard */
    }

    if (am_ctx != NULL) {
        allow_methods_arr = am_ctx->allow_methods;
        allow_methods_mode = am_ctx->allow_methods_mode;

    } else {
        allow_methods_arr = NULL;
        allow_methods_mode = 1; /* default: wildcard */
    }

    if (ah_ctx != NULL) {
        allow_headers_arr = ah_ctx->allow_headers;
        allow_headers_mode = ah_ctx->allow_headers_mode;

    } else {
        allow_headers_arr = NULL;
        allow_headers_mode = 1; /* default: wildcard */
    }

    if (eh_ctx != NULL) {
        expose_headers_arr = eh_ctx->expose_headers;

    } else {
        expose_headers_arr = NULL;
    }

    if (allow_credentials) {
        if (allow_origins_mode == 1) {
            allow_origins_mode = 2;

            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "\"cors_allow_origins *\" conflicts with "
                          "\"cors_allow_credentials on\", using "
                          "\"cors_allow_origins **\"");
        }

        if (allow_methods_mode == 1) {
            allow_methods_mode = 2;

            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "\"cors_allow_methods *\" conflicts with "
                          "\"cors_allow_credentials on\", using "
                          "\"cors_allow_methods **\"");
        }

        if (allow_headers_mode == 1) {
            allow_headers_mode = 2;

            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "\"cors_allow_headers *\" conflicts with "
                          "\"cors_allow_credentials on\", using "
                          "\"cors_allow_headers **\"");
        }
    }
#else
    enable = colcf->enable;
    allow_credentials = colcf->allow_credentials;
    max_age = colcf->max_age;
    allow_origins_arr = colcf->allow_origins;
#if (NGX_PCRE)
    allow_origins_regex_arr = colcf->allow_origins_regex;
#endif
    allow_methods_arr = colcf->allow_methods;
    allow_headers_arr = colcf->allow_headers;
    expose_headers_arr = colcf->expose_headers;
    allow_origins_mode = colcf->allow_origins_mode;
    allow_methods_mode = colcf->allow_methods_mode;
    allow_headers_mode = colcf->allow_headers_mode;
#endif

    if (!enable) {
        return ngx_http_next_header_filter(r);
    }

    if (r->method == NGX_HTTP_OPTIONS) {
        preflight = 1;

    } else {
        preflight = 0;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cors header filter");

    /* Step 1 */
    if (allow_origins_mode == 2) {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                                        &ngx_http_cors_request_origin_header);

        if (h == NULL) {
            if (allow_credentials) {
                allow_origin = NULL;

            } else {
                allow_origin = &ngx_http_cors_response_value_wildcard;
            }

        } else {
            allow_origin = &h->value;
        }

    } else if (allow_origins_mode == 1) {
        allow_origin = &ngx_http_cors_response_value_wildcard;

    } else {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                                        &ngx_http_cors_request_origin_header);

        if (h == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http cors origin header not found");
            goto leave;
        }

        allow_origin = &h->value;

        if (ngx_http_cors_search_list(allow_origins_arr, allow_origin, 1)) {
            goto step_2;
        }

#if (NGX_PCRE)
        if (allow_origins_regex_arr != NULL) {
            rc = ngx_regex_exec_array(allow_origins_regex_arr,
                                      allow_origin, r->connection->log);

            if (rc == NGX_OK) {
                goto step_2;
            }

            if (rc == NGX_ERROR) {
                return rc;
            }
        }

        /* NGX_DECLINED */
#endif

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http cors origin is not included in the list of "
                       "allow origins");
        goto leave;
    }

    /* Step 2 */
step_2:

    if (allow_methods_mode == 2) {
        allow_methods = &ngx_http_cors_response_methods_unbounded;

    } else if (allow_methods_mode == 1) {
        allow_methods = &ngx_http_cors_response_value_wildcard;

    } else if (!preflight) {
        allow_methods =
            ngx_http_cors_concatenate_list_value(r, allow_methods_arr);

    } else {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                                        &ngx_http_cors_request_method_header);
        if (h == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http cors request method header not found");
            goto leave;
        }

        method = ngx_http_cors_get_method(&h->value);
        if (method == NGX_HTTP_UNKNOWN) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http cors get unknown method");
            goto leave;
        }

        allow_methods = &h->value;
        if (!ngx_http_cors_search_list(allow_methods_arr,
                                       allow_methods, 0))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http cors request method \"%V\" is not included "
                           "in the list of allow methods", allow_methods);
            goto leave;
        }

        allow_methods =
            ngx_http_cors_concatenate_list_value(r, allow_methods_arr);
    }

    /* Step 3 */
    if (allow_headers_mode == 2) {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                                        &ngx_http_cors_request_headers_header);

        if (h == NULL) {
            if (allow_credentials) {
                allow_headers = NULL;

            } else {
                allow_headers = &ngx_http_cors_response_value_wildcard;
            }

        } else {
            allow_headers = &h->value;
        }

    } else if (allow_headers_mode == 1) {
        allow_headers = &ngx_http_cors_response_value_wildcard;

    } else if (!preflight) {
        allow_headers =
            ngx_http_cors_concatenate_list_value(r, allow_headers_arr);

    } else {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                                        &ngx_http_cors_request_headers_header);

        if (h == NULL) {
            allow_headers = ngx_http_cors_concatenate_list_value(r,
                                allow_headers_arr);

        } else {
            field_names = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
            if (field_names == NULL) {
                return NGX_ERROR;
            }

            if (ngx_http_cors_split_string(&h->value, ',', field_names)
                == NULL)
            {
                return NGX_ERROR;
            }

            if (!field_names->nelts) {
                return NGX_ERROR;
            }

            fnames = field_names->elts;
            for (i = 0; i < field_names->nelts; i++) {
                if (ngx_http_cors_search_string(
                        ngx_http_cors_safelisted_request_headers,
                        &fnames[i], 1))
                {
                    continue;
                }

                if (!ngx_http_cors_search_list(allow_headers_arr,
                                               &fnames[i], 1))
                {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http cors request header \"%V\" is not "
                                   "included in the list of allow headers",
                                   &fnames[i]);
                    allow_headers = NULL;
                }
            }

            allow_headers = ngx_http_cors_concatenate_list_value(r,
                                allow_headers_arr);
        }
    }

    /* Step 4 */
    if (ngx_http_cors_set_header(&r->headers_out.headers,
                &ngx_http_cors_response_origin_header, allow_origin)
            == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    /* Step 5 */
    if ((allow_origin == NULL || allow_origin->len == 0
         || ngx_strcmp(allow_origin->data, "*") != 0)
        && ngx_http_cors_add_header(&r->headers_out.headers,
                                    &ngx_http_cors_response_vary_header,
                                    &ngx_http_cors_request_origin_header)
            == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    /* Step 6 */
    if (allow_credentials
        && ngx_http_cors_set_header(&r->headers_out.headers,
                                    &ngx_http_cors_response_credential_header,
                                    &ngx_http_cors_response_value_true)
           == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    /* Step 7 */
    if (ngx_http_cors_set_header(&r->headers_out.headers,
                &ngx_http_cors_response_method_header, allow_methods)
            == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    /* Step 8 */
    if (ngx_http_cors_set_header(&r->headers_out.headers,
                &ngx_http_cors_response_headers_header, allow_headers)
            == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    /* Step 9 */
    if (expose_headers_arr && expose_headers_arr->nelts) {
        str_tmp = ngx_http_cors_concatenate_list_value(r,
                                                       expose_headers_arr);

        if (str_tmp && ngx_http_cors_set_header(&r->headers_out.headers,
                    &ngx_http_cors_response_expose_headers_header, str_tmp)
                == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    /* Step 10 */
    if (max_age) {
        str_max_age.data = ngx_pcalloc(r->pool, 64);
        if (str_max_age.data == NULL) {
            return NGX_ERROR;
        }

        last = ngx_snprintf(str_max_age.data, 64, "%T", max_age);
        str_max_age.len = last - str_max_age.data;

        if (ngx_http_cors_set_header(&r->headers_out.headers,
                    &ngx_http_cors_response_max_age_header, &str_max_age)
                == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cors header filter done");

    return ngx_http_next_header_filter(r);

leave:

    if (preflight) {
        r->headers_out.status = NGX_HTTP_FORBIDDEN;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_cors_search_list(ngx_array_t *arr, ngx_str_t *name,
    ngx_flag_t case_insensitive)
{
    ngx_uint_t                   i, hash;
    ngx_http_cors_val_t         *elt;

    if (arr == NULL || name == NULL || name->len == 0) {
        return 0;
    }

    if (case_insensitive) {
        hash = ngx_hash_key_lc(name->data, name->len);
    }

    else {
        hash = ngx_hash_key(name->data, name->len);
    }

    elt = arr->elts;

    for (i = 0; i < arr->nelts; i++) {
        if (elt[i].hash != hash) {
            continue;
        }

        if (!case_insensitive && elt[i].value.len == name->len
            && ngx_strncmp(elt[i].value.data, name->data, name->len) == 0)
        {
            return 1;
        }

        if (case_insensitive && elt[i].value.len == name->len
            && ngx_strncasecmp(elt[i].value.data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_cors_get_method(ngx_str_t *method)
{
    ngx_uint_t                     i;
    ngx_http_cors_method_name_t   *m;

    m = ngx_http_cors_methods_names;

    for (i = 0; /* void */; i++) {

        if (m[i].name == NULL) {
            break;
        }

        if (ngx_strlen(m[i].name) == method->len
            && ngx_strncmp(m[i].name, method->data, method->len) == 0)
        {
            return m[i].method;
        }
    }

    return NGX_HTTP_UNKNOWN;
}


static ngx_table_elt_t *
ngx_http_cors_search_header(ngx_list_t *list, ngx_str_t *name)
{
    ngx_uint_t                   i;
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;

    part = &list->part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == name->len
            && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            return &h[i];
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_cors_add_header(ngx_list_t *list, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    if (value->len == 0) {
        return NGX_OK;
    }

    h = ngx_list_push(list);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key = *key;
    h->value = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cors_set_header(ngx_list_t *list, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    h = ngx_http_cors_search_header(list, key);
    if (h == NULL) {
        if (value == NULL || value->len == 0) {
            return NGX_OK;
        }

        h = ngx_list_push(list);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;
        h->key = *key;
        h->value = *value;

    } else {
        if (value == NULL || value->len == 0) {
            h->hash = 0;
            return NGX_OK;
        }

        h->value = *value;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cors_search_string(ngx_str_t *string_array, ngx_str_t *name,
    ngx_flag_t case_insensitive)
{
    ngx_str_t *s;

    if (string_array == NULL || name == NULL || name->len == 0) {
        return 0;
    }

    s = string_array;
    while (s->len) {

        if (!case_insensitive && s->len == name->len
            && ngx_strncmp(s->data, name->data, name->len) == 0)
        {
            return 1;
        }

        if (case_insensitive && s->len == name->len
            && ngx_strncasecmp(s->data, name->data, name->len) == 0)
        {
            return 1;
        }

        s++;
    }

    return 0;
}


static ngx_str_t *
ngx_http_cors_concatenate_list_value(ngx_http_request_t *r,
    ngx_array_t *arr)
{
    size_t                       len;
    u_char                      *last, *end;
    ngx_str_t                   *s;
    ngx_uint_t                   i;
    ngx_http_cors_val_t         *elt;

    if (arr == NULL) {
        return NULL;
    }

    if (arr->nelts == 0) {
        return NULL;
    }

    elt = arr->elts;

    if (arr->nelts == 1) {
        return &elt->value;
    }

    len = 0;
    for (i = 0; i < arr->nelts; i++) {
        if (i == arr->nelts - 1) {
            len += elt[i].value.len;
            break;
        }

        len += elt[i].value.len + 1 + 1; /*GET, */
    }

    s = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (s == NULL) {
        return NULL;
    }

    s->data = ngx_palloc(r->pool, len);
    if (s->data == NULL) {
        return NULL;
    }

    last = s->data;
    end = s->data + len;

    for (i = 0; i < arr->nelts; i++) {

        if (i == arr->nelts - 1) {
            /* last element */
            last = ngx_snprintf(last, end - last, "%V", &elt[i].value);
            break;
        }

        last = ngx_snprintf(last, end - last, "%V, ", &elt[i].value);
    }

    s->len = last - s->data;

    return s;
}


static ngx_array_t *
ngx_http_cors_split_string(ngx_str_t *str,
    u_char separator, ngx_array_t *arr)
{
    u_char                      *pre, *p, *last;
    ngx_str_t                   *ts;

    last = str->data + str->len;
    pre = p = str->data;

    while (p < last) {

        ts = ngx_array_push(arr);
        if (ts == NULL) {
            return NULL;
        }

        p = ngx_strlchr(p, last, separator);
        if (p == NULL) {
            ts->data = pre;
            ts->len = last - pre;

            break;
        }

        ts->data = pre;
        ts->len = p - pre;

        p++;

        while ((p < last) && (*p == ' ')) {
            p++;
        }

        pre = p;
    }

    return arr;
}


static ngx_int_t
ngx_http_cors_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_cors_rewrite_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cors_header_filter;

    return NGX_OK;
}


#if (NGX_PCRE)
static ngx_int_t
ngx_http_add_allow_origin_regex(ngx_conf_t *cf,
    ngx_array_t *regex_array, ngx_str_t *name)
{
    ngx_regex_elt_t      *re;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    if (name->len == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty regex in \"%V\"", name);
        return NGX_ERROR;
    }

    re = ngx_array_push(regex_array);
    if (re == NULL) {
        return NGX_ERROR;
    }

    name->len--;
    name->data++;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *name;
    rc.pool = cf->pool;
    rc.options = NGX_REGEX_CASELESS;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    re->regex = rc.regex;
    re->name = name->data;

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_http_add_allow_origin(ngx_conf_t *cf,
    ngx_array_t *origins, ngx_str_t *value)
{
    ngx_http_cors_val_t   *cov;

    cov = ngx_array_push(origins);
    if (cov == NULL) {
        return NGX_ERROR;
    }

    cov->hash = ngx_hash_key(value->data, value->len);
    cov->value.data = value->data;
    cov->value.len = value->len;

    return NGX_OK;
}


#if (NGX_CONDITION)

static char *
ngx_http_cors_allow_origins(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t           *colcf = conf;

    ngx_str_t                          *value;
    ngx_uint_t                          i;
    ngx_http_cors_allow_origins_ctx_t  *ctx;
    ngx_condition_expr_id_t             expr_id;

    expr_id = ngx_condition_get_associated_expr_id(cf);

    if (colcf->allow_origins == NULL
        || colcf->allow_origins == NGX_CONF_UNSET_PTR)
    {
        colcf->allow_origins = ngx_array_create(cf->pool, 2,
            sizeof(ngx_http_cors_allow_origins_ctx_t));
        if (colcf->allow_origins == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_condition_find_expr_ctx(colcf->allow_origins, expr_id,
        sizeof(ngx_http_cors_allow_origins_ctx_t),
        offsetof(ngx_http_cors_allow_origins_ctx_t, expr_id));

    if (ctx == NULL) {
        ctx = ngx_array_push(colcf->allow_origins);
        if (ctx == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_allow_origins_ctx_t));

        ctx->expr_id = expr_id;
        ctx->allow_origins_mode = NGX_CONF_UNSET;
#if (NGX_PCRE)
        ctx->allow_origins_regex = NULL;
#endif
    }

    if (ctx->allow_origins_mode != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "*") == 0
        || ngx_strcmp(value[1].data, "**") == 0)
    {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other origins",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        ctx->allow_origins_mode = value[1].len == 1 ? 1 : 2;
        return NGX_CONF_OK;
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid origin \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "*") == 0
            || ngx_strcmp(value[i].data, "**") == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other origins",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        ctx->allow_origins_mode = 0;

#if (NGX_PCRE)
        if (value[i].data[0] == '~') {
            if (ctx->allow_origins_regex == NULL) {
                ctx->allow_origins_regex = ngx_array_create(cf->pool, 2,
                    sizeof(ngx_regex_elt_t));
                if (ctx->allow_origins_regex == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            if (ngx_http_add_allow_origin_regex(cf,
                ctx->allow_origins_regex, &value[i]) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }
#endif

        if (ctx->allow_origins == NULL) {
            ctx->allow_origins = ngx_array_create(cf->pool, 4,
                                                  sizeof(ngx_http_cors_val_t));
            if (ctx->allow_origins == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (ngx_http_add_allow_origin(cf, ctx->allow_origins,
            &value[i]) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_allow_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t           *colcf = conf;

    ngx_str_t                          *value;
    ngx_uint_t                          i, method;
    ngx_http_cors_val_t                *cov;
    ngx_http_cors_allow_methods_ctx_t  *ctx;
    ngx_condition_expr_id_t             expr_id;

    expr_id = ngx_condition_get_associated_expr_id(cf);

    if (colcf->allow_methods == NULL
        || colcf->allow_methods == NGX_CONF_UNSET_PTR)
    {
        colcf->allow_methods = ngx_array_create(cf->pool, 2,
            sizeof(ngx_http_cors_allow_methods_ctx_t));
        if (colcf->allow_methods == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_condition_find_expr_ctx(colcf->allow_methods, expr_id,
        sizeof(ngx_http_cors_allow_methods_ctx_t),
        offsetof(ngx_http_cors_allow_methods_ctx_t, expr_id));

    if (ctx == NULL) {
        ctx = ngx_array_push(colcf->allow_methods);
        if (ctx == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_allow_methods_ctx_t));

        ctx->expr_id = expr_id;
        ctx->allow_methods_mode = NGX_CONF_UNSET;
    }

    if (ctx->allow_methods_mode != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "*") == 0
        || ngx_strcmp(value[1].data, "**") == 0)
    {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other methods",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        ctx->allow_methods_mode = value[1].len == 1 ? 1 : 2;
        return NGX_CONF_OK;
    }

    if (ctx->allow_methods == NULL) {
        ctx->allow_methods = ngx_array_create(cf->pool, 4,
                                              sizeof(ngx_http_cors_val_t));
        if (ctx->allow_methods == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid method \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "*") == 0
            || ngx_strcmp(value[i].data, "**") == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other methods",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        ctx->allow_methods_mode = 0;

        cov = ngx_array_push(ctx->allow_methods);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        method = ngx_http_cors_get_method(&value[i]);
        if (method == NGX_HTTP_UNKNOWN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown method: \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_allow_headers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t            *colcf = conf;

    ngx_str_t                           *value;
    ngx_uint_t                           i;
    ngx_http_cors_val_t                 *cov;
    ngx_http_cors_allow_headers_ctx_t   *ctx;
    ngx_condition_expr_id_t              expr_id;

    expr_id = ngx_condition_get_associated_expr_id(cf);

    if (colcf->allow_headers == NULL
        || colcf->allow_headers == NGX_CONF_UNSET_PTR)
    {
        colcf->allow_headers = ngx_array_create(cf->pool, 2,
            sizeof(ngx_http_cors_allow_headers_ctx_t));
        if (colcf->allow_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_condition_find_expr_ctx(colcf->allow_headers, expr_id,
        sizeof(ngx_http_cors_allow_headers_ctx_t),
        offsetof(ngx_http_cors_allow_headers_ctx_t, expr_id));

    if (ctx == NULL) {
        ctx = ngx_array_push(colcf->allow_headers);
        if (ctx == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_allow_headers_ctx_t));

        ctx->expr_id = expr_id;
        ctx->allow_headers_mode = NGX_CONF_UNSET;
    }

    if (ctx->allow_headers_mode != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "*") == 0
        || ngx_strcmp(value[1].data, "**") == 0)
    {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other headers",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        ctx->allow_headers_mode = value[1].len == 1 ? 1 : 2;
        return NGX_CONF_OK;
    }

    if (ctx->allow_headers == NULL) {
        ctx->allow_headers = ngx_array_create(cf->pool, 4,
                                              sizeof(ngx_http_cors_val_t));
        if (ctx->allow_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx->allow_headers_mode = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid header \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "*") == 0
            || ngx_strcmp(value[i].data, "**") == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other headers",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_cors_search_string(
                ngx_http_cors_safelisted_request_headers, &value[i], 1))
        {
            continue;
        }

        cov = ngx_array_push(ctx->allow_headers);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key_lc(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_expose_headers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t              *colcf = conf;

    ngx_str_t                             *value;
    ngx_uint_t                             i;
    ngx_http_cors_val_t                   *cov;
    ngx_http_cors_expose_headers_ctx_t    *ctx;
    ngx_condition_expr_id_t                expr_id;

    expr_id = ngx_condition_get_associated_expr_id(cf);

    if (colcf->expose_headers == NULL
        || colcf->expose_headers == NGX_CONF_UNSET_PTR)
    {
        colcf->expose_headers = ngx_array_create(cf->pool, 2,
            sizeof(ngx_http_cors_expose_headers_ctx_t));
        if (colcf->expose_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_condition_find_expr_ctx(colcf->expose_headers, expr_id,
              sizeof(ngx_http_cors_expose_headers_ctx_t),
              offsetof(ngx_http_cors_expose_headers_ctx_t, expr_id));

    if (ctx == NULL) {
        ctx = ngx_array_push(colcf->expose_headers);
        if (ctx == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_expose_headers_ctx_t));

        ctx->expr_id = expr_id;
    }

    value = cf->args->elts;

    if (ctx->expose_headers == NULL) {
        ctx->expose_headers = ngx_array_create(cf->pool, 4,
                                               sizeof(ngx_http_cors_val_t));
        if (ctx->expose_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_http_cors_search_string(
                ngx_http_cors_safelisted_response_headers, &value[i], 1))
        {
            continue;
        }

        cov = ngx_array_push(ctx->expose_headers);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key_lc(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_cors_merge_conditional_allow_origins(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev)
{
    ngx_uint_t                           i;
    ngx_http_cors_allow_origins_ctx_t   *ctx, *new_ctx;
    ngx_condition_expr_id_t             *expr_id;

    if (*values == NULL || *values == NGX_CONF_UNSET_PTR
        || (*values)->nelts == 0)
    {
        if (prev != NULL
            && prev != NGX_CONF_UNSET_PTR
            && prev->nelts > 0)
        {
            *values = prev;
            return NGX_OK;
        }

        /* create default entry */
        *values = ngx_array_create(cf->pool, 1,
                                   sizeof(ngx_http_cors_allow_origins_ctx_t));
        if (*values == NULL) {
            return NGX_ERROR;
        }

        ctx = ngx_array_push(*values);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_allow_origins_ctx_t));

        ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
        ctx->allow_origins = NULL;
#if (NGX_PCRE)
        ctx->allow_origins_regex = NULL;
#endif
        ctx->allow_origins_mode = 1; /* default: wildcard */
    }

    /* Check if already has an unconditional entry */
    ctx = (*values)->elts;
    for (i = 0; i < (*values)->nelts; i++) {
        expr_id = &ctx[i].expr_id;
        if (*expr_id == NGX_CONDITION_NO_EXPR_ID) {
            return NGX_OK;
        }
    }

    /* No unconditional entry: append parent entries, then add default */
    if (prev != NULL
        && prev != NGX_CONF_UNSET_PTR
        && prev->nelts > 0)
    {
        ctx = prev->elts;

        for (i = 0; i < prev->nelts; i++) {
            new_ctx = ngx_array_push(*values);
            if (new_ctx == NULL) {
                return NGX_ERROR;
            }

            *new_ctx = ctx[i];
        }

        if (ngx_condition_find_expr_ctx(*values, NGX_CONDITION_NO_EXPR_ID,
                sizeof(ngx_http_cors_allow_origins_ctx_t),
                offsetof(ngx_http_cors_allow_origins_ctx_t, expr_id))
            != NULL)
        {
            return NGX_OK;
        }
    }

    ctx = ngx_array_push(*values);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(ctx, sizeof(ngx_http_cors_allow_origins_ctx_t));

    ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
    ctx->allow_origins = NULL;
#if (NGX_PCRE)
    ctx->allow_origins_regex = NULL;
#endif
    ctx->allow_origins_mode = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cors_merge_conditional_allow_methods(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev)
{
    ngx_uint_t                            i;
    ngx_http_cors_allow_methods_ctx_t    *ctx, *new_ctx;
    ngx_condition_expr_id_t              *expr_id;

    if (*values == NULL || *values == NGX_CONF_UNSET_PTR
        || (*values)->nelts == 0)
    {
        if (prev != NULL
            && prev != NGX_CONF_UNSET_PTR
            && prev->nelts > 0)
        {
            *values = prev;
            return NGX_OK;
        }

        *values = ngx_array_create(cf->pool, 1,
                                   sizeof(ngx_http_cors_allow_methods_ctx_t));
        if (*values == NULL) {
            return NGX_ERROR;
        }

        ctx = ngx_array_push(*values);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_allow_methods_ctx_t));

        ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
        ctx->allow_methods = NULL;
        ctx->allow_methods_mode = 1; /* default: wildcard */
    }

    ctx = (*values)->elts;
    for (i = 0; i < (*values)->nelts; i++) {
        expr_id = &ctx[i].expr_id;
        if (*expr_id == NGX_CONDITION_NO_EXPR_ID) {
            return NGX_OK;
        }
    }

    if (prev != NULL
        && prev != NGX_CONF_UNSET_PTR
        && prev->nelts > 0)
    {
        ctx = prev->elts;

        for (i = 0; i < prev->nelts; i++) {
            new_ctx = ngx_array_push(*values);
            if (new_ctx == NULL) {
                return NGX_ERROR;
            }

            *new_ctx = ctx[i];
        }

        if (ngx_condition_find_expr_ctx(*values, NGX_CONDITION_NO_EXPR_ID,
                sizeof(ngx_http_cors_allow_methods_ctx_t),
                offsetof(ngx_http_cors_allow_methods_ctx_t, expr_id))
            != NULL)
        {
            return NGX_OK;
        }
    }

    ctx = ngx_array_push(*values);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(ctx, sizeof(ngx_http_cors_allow_methods_ctx_t));

    ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
    ctx->allow_methods = NULL;
    ctx->allow_methods_mode = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cors_merge_conditional_allow_headers(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev)
{
    ngx_uint_t                             i;
    ngx_http_cors_allow_headers_ctx_t     *ctx, *new_ctx;
    ngx_condition_expr_id_t               *expr_id;

    if (*values == NULL || *values == NGX_CONF_UNSET_PTR
        || (*values)->nelts == 0)
    {
        if (prev != NULL
            && prev != NGX_CONF_UNSET_PTR
            && prev->nelts > 0)
        {
            *values = prev;
            return NGX_OK;
        }

        *values = ngx_array_create(cf->pool, 1,
                                   sizeof(ngx_http_cors_allow_headers_ctx_t));
        if (*values == NULL) {
            return NGX_ERROR;
        }

        ctx = ngx_array_push(*values);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_allow_headers_ctx_t));

        ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
        ctx->allow_headers = NULL;
        ctx->allow_headers_mode = 1; /* default: wildcard */
    }

    ctx = (*values)->elts;
    for (i = 0; i < (*values)->nelts; i++) {
        expr_id = &ctx[i].expr_id;
        if (*expr_id == NGX_CONDITION_NO_EXPR_ID) {
            return NGX_OK;
        }
    }

    if (prev != NULL
        && prev != NGX_CONF_UNSET_PTR
        && prev->nelts > 0)
    {
        ctx = prev->elts;

        for (i = 0; i < prev->nelts; i++) {
            new_ctx = ngx_array_push(*values);
            if (new_ctx == NULL) {
                return NGX_ERROR;
            }

            *new_ctx = ctx[i];
        }

        if (ngx_condition_find_expr_ctx(*values, NGX_CONDITION_NO_EXPR_ID,
                sizeof(ngx_http_cors_allow_headers_ctx_t),
                offsetof(ngx_http_cors_allow_headers_ctx_t, expr_id))
            != NULL)
        {
            return NGX_OK;
        }
    }

    ctx = ngx_array_push(*values);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(ctx, sizeof(ngx_http_cors_allow_headers_ctx_t));

    ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
    ctx->allow_headers = NULL;
    ctx->allow_headers_mode = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cors_merge_conditional_expose_headers(ngx_conf_t *cf,
    ngx_array_t **values, ngx_array_t *prev)
{
    ngx_uint_t                              i;
    ngx_http_cors_expose_headers_ctx_t     *ctx, *new_ctx;
    ngx_condition_expr_id_t                *expr_id;

    if (*values == NULL || *values == NGX_CONF_UNSET_PTR
        || (*values)->nelts == 0)
    {
        if (prev != NULL
            && prev != NGX_CONF_UNSET_PTR
            && prev->nelts > 0)
        {
            *values = prev;
            return NGX_OK;
        }

        *values = ngx_array_create(cf->pool, 1,
                                   sizeof(ngx_http_cors_expose_headers_ctx_t));
        if (*values == NULL) {
            return NGX_ERROR;
        }

        ctx = ngx_array_push(*values);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(ctx, sizeof(ngx_http_cors_expose_headers_ctx_t));

        ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
        ctx->expose_headers = NULL;
    }

    ctx = (*values)->elts;
    for (i = 0; i < (*values)->nelts; i++) {
        expr_id = &ctx[i].expr_id;
        if (*expr_id == NGX_CONDITION_NO_EXPR_ID) {
            return NGX_OK;
        }
    }

    if (prev != NULL
        && prev != NGX_CONF_UNSET_PTR
        && prev->nelts > 0)
    {
        ctx = prev->elts;

        for (i = 0; i < prev->nelts; i++) {
            new_ctx = ngx_array_push(*values);
            if (new_ctx == NULL) {
                return NGX_ERROR;
            }

            *new_ctx = ctx[i];
        }

        if (ngx_condition_find_expr_ctx(*values, NGX_CONDITION_NO_EXPR_ID,
                sizeof(ngx_http_cors_expose_headers_ctx_t),
                offsetof(ngx_http_cors_expose_headers_ctx_t, expr_id))
            != NULL)
        {
            return NGX_OK;
        }
    }

    ctx = ngx_array_push(*values);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(ctx, sizeof(ngx_http_cors_expose_headers_ctx_t));

    ctx->expr_id = NGX_CONDITION_NO_EXPR_ID;
    ctx->expose_headers = NULL;

    return NGX_OK;
}

#else

static char *
ngx_http_cors_allow_origins(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t  *colcf = conf;

    ngx_str_t                 *value;
    ngx_uint_t                 i;

    value = cf->args->elts;

    if (colcf->allow_origins_mode != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "*") == 0
        || ngx_strcmp(value[1].data, "**") == 0)
    {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other origins",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        colcf->allow_origins_mode = value[1].len == 1 ? 1 : 2;
        return NGX_CONF_OK;
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid origin \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "*") == 0
            || ngx_strcmp(value[i].data, "**") == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other origins",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        colcf->allow_origins_mode = 0;

#if (NGX_PCRE)
        if (value[i].data[0] == '~') {
            if (colcf->allow_origins_regex == NGX_CONF_UNSET_PTR) {
                colcf->allow_origins_regex = ngx_array_create(cf->pool, 2,
                    sizeof(ngx_regex_elt_t));
                if (colcf->allow_origins_regex == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            if (ngx_http_add_allow_origin_regex(cf,
                colcf->allow_origins_regex, &value[i]) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }
#endif

        if (colcf->allow_origins == NULL) {
            colcf->allow_origins = ngx_array_create(cf->pool, 4,
                sizeof(ngx_http_cors_val_t));
            if (colcf->allow_origins == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (ngx_http_add_allow_origin(cf, colcf->allow_origins,
            &value[i]) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_allow_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t  *colcf = conf;

    ngx_str_t                 *value;
    ngx_uint_t                 i, method;
    ngx_http_cors_val_t       *cov;

    if (colcf->allow_methods_mode != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "*") == 0
        || ngx_strcmp(value[1].data, "**") == 0)
    {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other methods",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        colcf->allow_methods_mode = value[1].len == 1 ? 1 : 2;
        return NGX_CONF_OK;
    }

    if (colcf->allow_methods == NULL) {
        colcf->allow_methods = ngx_array_create(cf->pool, 4,
                                                sizeof(ngx_http_cors_val_t));
        if (colcf->allow_methods == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid method \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "*") == 0
            || ngx_strcmp(value[i].data, "**") == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other methods",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        colcf->allow_methods_mode = 0;

        cov = ngx_array_push(colcf->allow_methods);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        method = ngx_http_cors_get_method(&value[i]);
        if (method == NGX_HTTP_UNKNOWN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown method: \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_allow_headers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t  *colcf = conf;

    ngx_str_t                 *value;
    ngx_uint_t                 i;
    ngx_http_cors_val_t       *cov;

    if (colcf->allow_headers_mode != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "*") == 0
        || ngx_strcmp(value[1].data, "**") == 0)
    {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other headers",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        colcf->allow_headers_mode = value[1].len == 1 ? 1 : 2;
        return NGX_CONF_OK;
    }

    if (colcf->allow_headers == NULL) {
        colcf->allow_headers = ngx_array_create(cf->pool, 4,
                                                sizeof(ngx_http_cors_val_t));
        if (colcf->allow_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    colcf->allow_headers_mode = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid header \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "*") == 0
            || ngx_strcmp(value[i].data, "**") == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other headers",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_cors_search_string(
                ngx_http_cors_safelisted_request_headers, &value[i], 1))
        {
            continue;
        }

        cov = ngx_array_push(colcf->allow_headers);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key_lc(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_expose_headers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t  *colcf = conf;

    ngx_str_t                 *value;
    ngx_uint_t                 i;
    ngx_http_cors_val_t       *cov;

    value = cf->args->elts;

    if (colcf->expose_headers == NULL) {
        colcf->expose_headers = ngx_array_create(cf->pool, 4,
                                                 sizeof(ngx_http_cors_val_t));
        if (colcf->expose_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_http_cors_search_string(
                ngx_http_cors_safelisted_response_headers, &value[i], 1))
        {
            continue;
        }

        cov = ngx_array_push(colcf->expose_headers);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key_lc(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}

#endif


static void *
ngx_http_cors_create_conf(ngx_conf_t *cf)
{
    ngx_http_cors_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cors_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->allow_origins = NULL;
     *     conf->allow_methods = NULL;
     *     conf->allow_headers = NULL;
     *     conf->expose_headers = NULL;
     *     conf->preflight_status = 0;
     *
     */

#if (NGX_CONDITION)
    conf->allow_origins = NGX_CONF_UNSET_PTR;
    conf->allow_methods = NGX_CONF_UNSET_PTR;
    conf->allow_headers = NGX_CONF_UNSET_PTR;
    conf->expose_headers = NGX_CONF_UNSET_PTR;
    conf->enable = NGX_CONF_UNSET_PTR;
    conf->allow_credentials = NGX_CONF_UNSET_PTR;
    conf->preflight_status = NGX_CONF_UNSET_PTR;
    conf->max_age = NGX_CONF_UNSET_PTR;
#else
#if (NGX_PCRE)
    conf->allow_origins_regex = NGX_CONF_UNSET_PTR;
#endif

    conf->enable = NGX_CONF_UNSET;
    conf->allow_origins_mode = NGX_CONF_UNSET;
    conf->allow_methods_mode = NGX_CONF_UNSET;
    conf->allow_headers_mode = NGX_CONF_UNSET;
    conf->allow_credentials = NGX_CONF_UNSET;
    conf->max_age = NGX_CONF_UNSET;
    conf->preflight_status = NGX_CONF_UNSET_UINT;
#endif

    return conf;
}


static char *
ngx_http_cors_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cors_loc_conf_t *prev = parent;
    ngx_http_cors_loc_conf_t *conf = child;

#if (NGX_CONDITION)
    if (ngx_http_cors_merge_conditional_allow_origins(cf,
            &conf->allow_origins, prev->allow_origins) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_cors_merge_conditional_allow_methods(cf,
            &conf->allow_methods, prev->allow_methods) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_cors_merge_conditional_allow_headers(cf,
            &conf->allow_headers, prev->allow_headers) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_cors_merge_conditional_expose_headers(cf,
            &conf->expose_headers, prev->expose_headers) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_flag_value(cf, &conf->enable,
            prev->enable, 0) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_flag_value(cf, &conf->allow_credentials,
            prev->allow_credentials, 0) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_sec_value(cf, &conf->max_age,
            prev->max_age, 0) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_conditional_enum_value(cf, &conf->preflight_status,
            prev->preflight_status, NGX_HTTP_NO_CONTENT) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#else
    if (conf->allow_origins_mode == NGX_CONF_UNSET) {
        conf->allow_origins = prev->allow_origins;
#if (NGX_PCRE)
        ngx_conf_merge_ptr_value(conf->allow_origins_regex,
                                 prev->allow_origins_regex, NULL);
#endif
        ngx_conf_merge_value(conf->allow_origins_mode,
                             prev->allow_origins_mode, 1);

#if (NGX_PCRE)

    } else if (conf->allow_origins_regex == NGX_CONF_UNSET_PTR) {
        conf->allow_origins_regex = NULL;
#endif
    }

    if (conf->allow_methods_mode == NGX_CONF_UNSET) {
        conf->allow_methods = prev->allow_methods;
        ngx_conf_merge_value(conf->allow_methods_mode,
                             prev->allow_methods_mode, 1);
    }

    if (conf->allow_headers_mode == NGX_CONF_UNSET) {
        conf->allow_headers = prev->allow_headers;
        ngx_conf_merge_value(conf->allow_headers_mode,
                             prev->allow_headers_mode, 1);
    }

    if (conf->expose_headers == NULL) {
        conf->expose_headers = prev->expose_headers;
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->allow_credentials, prev->allow_credentials, 0);
    ngx_conf_merge_sec_value(conf->max_age, prev->max_age, 0);
    ngx_conf_merge_uint_value(conf->preflight_status, prev->preflight_status,
        NGX_HTTP_NO_CONTENT);
#endif

#if !(NGX_CONDITION)
    /* Validate allow_credentials conflicts with wildcard modes */

    if (conf->allow_credentials == 1) {
        if (conf->allow_origins_mode == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"cors_allow_origins\" can not be \"*\" if "
                               "\"cors_allow_credentials\" is enabled");
            return NGX_CONF_ERROR;
        }

        if (conf->allow_methods_mode == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"cors_allow_methods\" can not be \"*\" if "
                               "\"cors_allow_credentials\" is enabled");
            return NGX_CONF_ERROR;
        }

        if (conf->allow_headers_mode == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"cors_allow_headers\" can not be \"*\" if "
                               "\"cors_allow_credentials\" is enabled");
            return NGX_CONF_ERROR;
        }
    }
#endif

    return NGX_CONF_OK;
}
