

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


typedef struct {
    u_char                    *name;
    uint32_t                   method;
} ngx_http_cors_method_name_t;


typedef struct ngx_http_cors_val_s {
    ngx_uint_t                 hash;
    ngx_str_t                  value;
} ngx_http_cors_val_t;


typedef struct {
    ngx_array_t               *allow_origins;
#if (NGX_PCRE)
    ngx_array_t               *allow_origins_regex;
#endif
    ngx_array_t               *allow_methods;
    ngx_array_t               *allow_headers;
    ngx_array_t               *expose_headers;
    ngx_flag_t                 enable;
    ngx_int_t                  origin_unbounded;
    ngx_int_t                  method_unbounded;
    ngx_int_t                  header_unbounded;
    ngx_flag_t                 allow_credentials;
    time_t                     max_age;

    ngx_uint_t                 preflight_status;
} ngx_http_cors_loc_conf_t;


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

static char *ngx_http_cors_allow_origins(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_allow_methods(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_allow_headers(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_expose_headers(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);



static ngx_conf_enum_t  ngx_http_cors_preflight_status[] = {
    { ngx_string("200"), NGX_HTTP_OK },
    { ngx_string("204"), NGX_HTTP_NO_CONTENT },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_cors_commands[] = {

    { ngx_string("cors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, enable),
      NULL },

    { ngx_string("cors_allow_origins"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_allow_origins,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_allow_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_allow_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_allow_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_allow_headers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_expose_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_expose_headers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cors_max_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, max_age),
      NULL },

    { ngx_string("cors_allow_credentials"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, allow_credentials),
      NULL },

    { ngx_string("cors_preflight_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cors_loc_conf_t, preflight_status),
      &ngx_http_cors_preflight_status },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_cors_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_cors_init,                         /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_cors_create_conf,                  /* create location configuration */
    ngx_http_cors_merge_conf                    /* merge location configuration */
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
static ngx_str_t ngx_http_cors_response_value_empty = ngx_string("");
static ngx_str_t ngx_http_cors_response_methods_unbounded =
    ngx_string("GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH");

/* case-sensitive */
static ngx_str_t ngx_http_cors_simple_methods[] = {
    ngx_string("GET"),
    ngx_string("HEAD"),
    ngx_string("POST"),
    { 0, NULL }
};

/* case-insensitive */
static ngx_str_t ngx_http_cors_safelisted_request_headers[] = {
    ngx_string("Accept"),
    ngx_string("Accept-Language"),
    ngx_string("Content-Language"),
    ngx_string("Content-Type"),
    ngx_string("Range"),
}

#if 0
/* case-insensitive */
static ngx_str_t simple_types[] = {
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
    ngx_http_cors_loc_conf_t         *colcf;
    ngx_int_t                         rc;

    colcf = ngx_http_get_module_loc_conf(r, ngx_http_cors_module);

    if (!colcf->enable) {
        return NGX_DECLINED;
    }

    if (r->method != NGX_HTTP_OPTIONS) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cors rewrite handler \"%V\"", &r->uri);

    r->headers_out.status = colcf->preflight_status;
    r->headers_out.content_type.len = 0;
    r->header_only = 1;

    return ngx_http_finalize_request(r, rc);
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

    colcf = ngx_http_get_module_loc_conf(r, ngx_http_cors_module);

    if (!colcf->enable) {
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
    if (colcf->origin_unbounded == 2) {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                &ngx_http_cors_request_origin_header);

        if (h == NULL) {
            if (colcf->allow_credentials) {
                allow_origin = &ngx_http_cors_response_value_empty;
            } else {
                allow_origin = &ngx_http_cors_response_value_wildcard;
            }
        } else {
            allow_origin = &h->value;
        }

    } else if (colcf->origin_unbounded == 1) {
        allow_origin = &ngx_http_cors_response_value_wildcard;

    } else {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                &ngx_http_cors_request_origin_header);

        if (h == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http cors origin header not found");
            goto next_filter;

        }

        allow_origin = &h->value;

        if (ngx_http_cors_search_list(colcf->allow_origins, allow_origin, 0)) {
            goto step_2;
        }

#if (NGX_PCRE)
        if (colcf->allow_origins_regex) {
            rc = ngx_regex_exec_array(colcf->allow_origins_regex,
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
            "http cors origin is not included in the list of allow origins");
        goto next_filter;
    }

    /* Step 2 */
step_2:
    if (colcf->method_unbounded == 2) {
        allow_methods = &ngx_http_cors_response_methods_unbounded;

    } else if (colcf->method_unbounded == 1) {
        allow_methods = &ngx_http_cors_response_value_wildcard;

    } else if (!preflight) {
        allow_methods = ngx_http_cors_concatenate_list_value(r,
            colcf->allow_methods);

    } else {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                &ngx_http_cors_request_method_header);
        if (h == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http cors request method header not found");
            goto next_filter;
        }

        method = ngx_http_cors_get_method(&h->value);
        if (method == NGX_HTTP_UNKNOWN) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http cors get unknown method");
            goto next_filter;
        }

        allow_methods = &h->value;
        if (!ngx_http_cors_search_list(colcf->allow_methods,
            allow_methods, 0))
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http cors request method \"%V\" is not included in "
                "the list of allow methods", allow_methods);
            goto next_filter;
        }

        allow_methods = ngx_http_cors_concatenate_list_value(r,
            colcf->allow_methods);
    }

    /* Step 3 */
    if (colcf->header_unbounded == 2) {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                &ngx_http_cors_request_headers_header);

        if (h == NULL) {
            if (colcf->allow_credentials) {
                allow_headers = &ngx_http_cors_response_value_empty;
            } else {
                allow_headers = &ngx_http_cors_response_value_wildcard;
            }
        } else {
            allow_headers = &h->value;
        }

    } else if (colcf->header_unbounded == 1) {
        allow_headers = &ngx_http_cors_response_value_wildcard;

    } else if (!preflight) {
        allow_headers = ngx_http_cors_concatenate_list_value(r,
            colcf->allow_headers);

    } else {
        h = ngx_http_cors_search_header(&r->headers_in.headers,
                &ngx_http_cors_request_headers_header);

        if (h == NULL) {
            allow_headers = ngx_http_cors_concatenate_list_value(r,
            colcf->allow_headers);

        } else {
            field_names = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
            if (field_names == NULL) {
                return NGX_ERROR;
            }

            if (ngx_http_cors_split_string(&h->value, ',',
                        field_names) == NULL) {
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

                if (!ngx_http_cors_search_list(colcf->allow_headers,
                            &fnames[i], 1))
                {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "http cors request header \"%V\" is not included in "
                        "the list of allow headers");
                    allow_headers = &ngx_http_cors_response_value_empty;
                }
            }

            allow_headers = ngx_http_cors_concatenate_list_value(r,
            colcf->allow_headers);
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
    if (ngx_strcmp(allow_origin.data, "*") != 0
        && ngx_http_cors_add_header(&r->headers_out.headers,
                &ngx_http_cors_response_vary_header,
                &ngx_http_cors_request_origin_header)
            == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    /* Step 6 */
    if (colcf->allow_credentials
        && ngx_http_cors_set_header(&r->headers_out.headers,
            &ngx_http_cors_response_credential_header,
            &ngx_http_cors_response_value_true) == NGX_ERROR)
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
    if (colcf->expose_headers && colcf->expose_headers->nelts) {
        str_tmp = ngx_http_cors_concatenate_list_value(r,
                colcf->expose_headers);

        if (str_tmp && ngx_http_cors_set_header(&r->headers_out.headers,
                    &ngx_http_cors_response_expose_headers_header, str_tmp)
                == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    /* Step 10 */
    if (colcf->max_age) {
        str_max_age.data = ngx_pcalloc(r->pool, 64);
        if (str_max_age.data == NULL) {
            return NGX_ERROR;
        }

        last = ngx_snprintf(str_max_age.data, 64, "%T", colcf->max_age);
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

next_filter:

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
    ngx_uint_t                           i;
    ngx_http_cors_method_name_t *m;

    m = ngx_http_cors_methods_names;

    for (i = 0; /* void */; i++) {

        if (m[i].name == NULL) {
            break;
        }

        if (ngx_strncmp(m[i].name, method->data, method->len) == 0)
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
    } else {
        if (value->len == 0) {
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
    ngx_http_cors_val_t *elt;

    if (arr == NULL) {
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

    while(p < last) {

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
    ngx_array_t *origins, ngx_str_t *name)
{
    ngx_regex_elt_t      *re;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    if (name->len == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "empty regex in \"%V\"", name);
        return NGX_ERROR;
    }

    if (origins == NGX_CONF_UNSET_PTR) {
        origins = ngx_array_create(cf->pool, 2, sizeof(ngx_regex_elt_t));
        if (origins == NULL) {
            return NGX_ERROR;
        }
    }

    re = ngx_array_push(origins);
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

    if (origins == NULL) {
        origins = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cors_val_t));
        if (origins == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cov = ngx_array_push(origins);
    if (cov == NULL) {
        return NGX_CONF_ERROR;
    }

    cov->hash = ngx_hash_key(value.data, value.len);
    cov->value = value;
}


static char *
ngx_http_cors_allow_origins(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cors_loc_conf_t  *colcf = conf;

    ngx_str_t                 *value;
    ngx_uint_t                 i;
    ngx_http_cors_val_t       *cov;

    value = cf->args->elts;

    colcf->origin_unbounded = 0;

    if (ngx_strcmp(value[1].data, "*") == 0) {
        colcf->origin_unbounded = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "**") == 0) {
        colcf->origin_unbounded = 2;
        return NGX_CONF_OK;
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid origin \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "*") == 0
            || ngx_strcmp(value[i].data, "**"))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other origins",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

#if (NGX_PCRE)
        if (value[i].data[0] == '~') {
            if (ngx_http_add_allow_origin_regex(cf,
                colcf->allow_origins_regex, &value[i]) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }
#endif

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

    value = cf->args->elts;

    colcf->method_unbounded = 0;

    if (ngx_strcmp(value[1].data, "*") == 0) {
        colcf->method_unbounded = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "**") == 0) {
        colcf->method_unbounded = 2;
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
            || ngx_strcmp(value[i].data, "**"))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other methods",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

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

    value = cf->args->elts;

    colcf->header_unbounded = 0;

    if (ngx_strcmp(value[1].data, "*") == 0) {
        colcf->header_unbounded = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "**") == 0) {
        colcf->header_unbounded = 2;
        return NGX_CONF_OK;
    }

    if (colcf->allow_headers == NULL) {
        colcf->allow_headers = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cors_val_t));
        if (colcf->allow_headers == NULL) {
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
            || ngx_strcmp(value[i].data, "**"))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" cannot be used with other headers",
                               &value[i]);
            return NGX_CONF_ERROR;
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

        if (ngx_http_cors_search_string(ngx_http_cors_safelisted_response_headers,
                    &value[i], 1)) {
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
     *     conf->allow_origins_regex = NULL;
     *     conf->allow_methods = NULL;
     *     conf->allow_headers = NULL;
     *     conf->expose_headers = NULL;
     *     conf->preflight_status = 0;
     *
     */

    conf->enable = NGX_CONF_UNSET;
    conf->origin_unbounded = NGX_CONF_UNSET;
    conf->method_unbounded = NGX_CONF_UNSET;
    conf->header_unbounded = NGX_CONF_UNSET;
    conf->allow_credentials = NGX_CONF_UNSET;
    conf->max_age = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_cors_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cors_loc_conf_t *prev = parent;
    ngx_http_cors_loc_conf_t *conf = child;

    if (conf->allow_origins == NULL
        && conf->allow_origins_regex == NULL
        && conf->origin_unbounded == NGX_CONF_UNSET)
    {
        conf->allow_origins = prev->allow_origins;
        conf->allow_origins_regex = prev->allow_origins_regex;
        ngx_conf_merge_value(conf->origin_unbounded, prev->origin_unbounded,
            1);
    }

    if (conf->allow_methods == NULL
        && conf->method_unbounded == NGX_CONF_UNSET)
    {
        conf->allow_methods = prev->allow_methods;
        ngx_conf_merge_value(conf->method_unbounded, prev->method_unbounded, 1);
    }

    if (conf->allow_headers == NULL
        && conf->header_unbounded == NGX_CONF_UNSET)
    {
        conf->allow_headers = prev->allow_headers;
        ngx_conf_merge_value(conf->header_unbounded, prev->header_unbounded, 1);
    }

    if (conf->expose_headers == NULL) {
        conf->expose_headers = prev->expose_headers;
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->allow_credentials, prev->allow_credentials, 0);
    ngx_conf_merge_sec_value(conf->max_age, prev->max_age, 0);
    ngx_conf_merge_uint_value(conf->preflight_status, prev->preflight_status,
        NGX_HTTP_OK);

    if (conf->allow_credentials == 1) {
        if (conf->origin_unbounded == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"cors_allow_origins\" can not be \"*\" if "
                               "\"cors_allow_credential\" is enabled");
            return NGX_CONF_ERROR;
        }

        if (conf->method_unbounded == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"cors_allow_methods\" can not be \"*\" if "
                               "\"cors_allow_credential\" is enabled");
            return NGX_CONF_ERROR;
        }

        if (conf->header_unbounded == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"cors_allow_headers\" can not be \"*\" if "
                               "\"cors_allow_credential\" is enabled");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
