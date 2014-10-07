/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_auth_memcookie_module: memcached cookies authentication
 * 
 * Autor: Mathieu CARBONNEAUX
 * 
 */

/* Chas Woodfield 7th October 2014
 * Merged the 2 versions https://github.com/richp10/apache2-mod_auth_memcookie-1.0.3 and https://github.com/raghu600/apache2-mod_auth_memcookie
 * Added an extra couple of config options:
 *     Auth_memCookie_RedirectURLOnFailure ... If authorisation fails then redirect to the specified url
 *     Auth_memCookie_AcceptPathStart ........ If authorisation fails and the path starts with the specified string, then accept the authorisation
 * Both of the above configuration settings can be achieved using apache config, but I was struggling to get it right,
 * I did eventually get it right, but have chosen to leave these options in as it makes the config simpler.
 * Added an extra couple of options for checking the remote IP, use Client-IP header and use X-Forwarded-For header if Client-IP header is not set
 * Changed the authorisation to loop through the requires, so it must match all the require directives
 * Authorisation will now check multiple groups and users in the require directives
 * Configuration is now merged if you have configuration at multiple levels
 * Fixed a few bugs in authorisation
 * I havn't checked the creation of entries within memcached as we create the entries in another application
 * Feels like I have done more, but I think that was down to frustration of debugging while doing other stuff, so havn't intentionally omitted any changes
*/ 
/* changed by mls in 2011-04:
 *
 * - ported the code to libmemcached.
 * - made sure that the session data contains no \r or \n.
 * - made sure that the cookie is a valid md5sum.
 * - added Auth_memCookie_SessionHeaders option to specify which
 *   headers should be cleared from the input headers and taken from
 *   the session data.
 * - added szAuth_memCookie_AuthentificationURI to configure that
 *   the session is created by doing a subrequest to the specfied
 *   URI and using the returned headers (uses the configured
 *   SessionHeaders).
 * - added Auth_memCookie_AuthentificationHeader option to tell the
 *   module that it can take the user name from the specified header
 *   when it creates the session.
 * - added Auth_memCookie_AuthentificationURIOnlyAuth to make it
 *   just run the authentification steps for the subrequest
 *   (data is taken from the input headers in that case).
 * - added Auth_memCookie_CookieDomain to specify a domain for the
 *   session cookie.
 * - added Auth_memCookie_AllowAnonymous to specify that no session
 *   is required for the request.
 * - added Auth_memCookie_CommandHeader to specify a way to issue
 *   commands for session managemant: "login" makes it ignore the
 *   AllowAnonymous flag, "logout" deletes the session.
 */

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_md5.h"            /* for apr_password_validate */
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_main.h" /* For ap_server_conf */
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "http_vhost.h"
#include "apr_base64.h"

#include "memcached.h"

#define ERRTAG "Auth_memCookie: "
#define VERSION "1.0.4k"


/* Values for Auth_memCookie_MatchIP_Mode, it will always fall back on the remote IP, if it cannot determine the IP by other means */
#define IP_MATCH_NOT_SET               0 /* Do not check IP */
#define IP_MATCH_X_FORWARDED           1 /* Use the X-Forwarded-For header */
#define IP_MATCH_VIA                   2 /* Use the Via header */
#define IP_MATCH_REMOTE                3 /* Just use the remote ip address */
#define IP_MATCH_CLIENT_IP             4 /* Use the Client-IP header */
#define IP_MATCH_CLIENT_IP_X_FORWARDED 5 /* Use the Client-IP header if defined, if not defined use the X-Forwarded-For header */

/* apache module name */
module AP_MODULE_DECLARE_DATA mod_auth_memcookie_module;

typedef struct {
    bool isSet;
    char *value;
} strConfigSetting;

typedef struct {
    bool isSet;
    int value;
} intConfigSetting;

/* config structure */
typedef struct {
    strConfigSetting   szAuth_memCookie_memCached_addr;
    apr_time_t         tAuth_memCookie_MemcacheObjectExpiry;
    intConfigSetting   nAuth_memCookie_MemcacheObjectExpiryReset;

    intConfigSetting   nAuth_memCookie_SetSessionHTTPHeader;
    intConfigSetting   nAuth_memCookie_SetSessionHTTPHeaderEncode;
    intConfigSetting   nAuth_memCookie_SessionTableSize;

    strConfigSetting   szAuth_memCookie_CookieName;
    strConfigSetting   szAuth_memCookie_CookieDomain;

    intConfigSetting   nAuth_memCookie_GroupAuthoritative;
    intConfigSetting   nAuth_memCookie_Authoritative;
    intConfigSetting   nAuth_memCookie_MatchIP_Mode;

    intConfigSetting   nAuth_memCookie_authbasicfix;
    apr_array_header_t *requireelems;

    strConfigSetting   szAuth_memCookie_AuthentificationURI;
    strConfigSetting   szAuth_memCookie_AuthentificationHeader;
    strConfigSetting   szAuth_memCookie_SessionHeaders;
    strConfigSetting   szAuth_memCookie_CommandHeader;
    intConfigSetting   nAuth_memCookie_AllowAnonymous;
    intConfigSetting   nAuth_memCookie_AuthentificationURIOnlyAuth;

    strConfigSetting   szAuth_memCookie_AcceptPathStart;
    strConfigSetting   szAuth_memCookie_RedirectURLOnFailure;
} strAuth_memCookie_config_rec;

static void logString(char *name, char *value) {
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, ap_server_conf, ERRTAG "Chas: Config Name: %s, Value: %s", name, ((value == NULL) ? "Null" : value));
}

static void logInt(char *name, int value) {
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, ap_server_conf, ERRTAG "Chas: Config Name: %s, Value: %d", name, value);
}

static void dumpConf1(strAuth_memCookie_config_rec *conf, char *name) {
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, ap_server_conf, ERRTAG "Chas: Dump Config pointer %pp from Name: %s", conf, name);
    logString("szAuth_memCookie_memCached_addr", conf->szAuth_memCookie_memCached_addr.value);
    logInt("nAuth_memCookie_MemcacheObjectExpiryReset", conf->nAuth_memCookie_MemcacheObjectExpiryReset.value);
    logInt("nAuth_memCookie_SetSessionHTTPHeader", conf->nAuth_memCookie_SetSessionHTTPHeader.value);
    logInt("nAuth_memCookie_SetSessionHTTPHeaderEncode", conf->nAuth_memCookie_SetSessionHTTPHeaderEncode.value);
    logInt("nAuth_memCookie_SessionTableSize", conf->nAuth_memCookie_SessionTableSize.value);
    logString("szAuth_memCookie_CookieName", conf->szAuth_memCookie_CookieName.value);
    logString("szAuth_memCookie_CookieDomain", conf->szAuth_memCookie_CookieDomain.value);
    logInt("nAuth_memCookie_GroupAuthoritative", conf->nAuth_memCookie_GroupAuthoritative.value);
    logInt("nAuth_memCookie_Authoritative", conf->nAuth_memCookie_Authoritative.value);
    logInt("nAuth_memCookie_MatchIP_Mode", conf->nAuth_memCookie_MatchIP_Mode.value);
    logInt("nAuth_memCookie_authbasicfix", conf->nAuth_memCookie_authbasicfix.value);
    logString("szAuth_memCookie_AuthentificationURI", conf->szAuth_memCookie_AuthentificationURI.value);
    logString("szAuth_memCookie_AuthentificationHeader", conf->szAuth_memCookie_AuthentificationHeader.value);
    logString("szAuth_memCookie_SessionHeaders", conf->szAuth_memCookie_SessionHeaders.value);
    logString("szAuth_memCookie_CommandHeader", conf->szAuth_memCookie_CommandHeader.value);
    logInt("nAuth_memCookie_AllowAnonymous", conf->nAuth_memCookie_AllowAnonymous.value);
    logInt("nAuth_memCookie_AuthentificationURIOnlyAuth", conf->nAuth_memCookie_AuthentificationURIOnlyAuth.value);
    logString("szAuth_memCookie_RedirectURLOnFailure", conf->szAuth_memCookie_RedirectURLOnFailure.value);
    logString("szAuth_memCookie_AcceptPathStart", conf->szAuth_memCookie_AcceptPathStart.value);
}

static void dumpConf(request_rec *r, char *name) {
    strAuth_memCookie_config_rec *conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);
    dumpConf1(conf, name);
}

extern ap_conf_vector_t * ap_create_request_config(apr_pool_t *p);

/* copied from apache's request.c :-( */
static request_rec *make_sub_request(const request_rec *r)
{
    apr_pool_t *rrp;
    request_rec *rnew;
    apr_pool_create(&rrp, r->pool);
    apr_pool_tag(rrp, "subrequest");
    rnew = apr_pcalloc(rrp, sizeof(request_rec));
    rnew->pool = rrp;
    rnew->hostname       = r->hostname;

    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;
    rnew->request_config = ap_create_request_config(rnew->pool);
    rnew->per_dir_config = r->server->lookup_defaults;
    rnew->htaccess = r->htaccess;
    rnew->allowed_methods = ap_make_method_list(rnew->pool, 2);
    ap_copy_method_list(rnew->allowed_methods, r->allowed_methods);
    rnew->proto_input_filters = r->proto_input_filters;
    rnew->proto_output_filters = r->proto_output_filters;
    rnew->input_filters = r->proto_input_filters;
    rnew->output_filters = r->proto_output_filters;
    ap_set_sub_req_protocol(rnew, r);
    ap_run_create_request(rnew);
    rnew->used_path_info = AP_REQ_DEFAULT_PATH_INFO;
    return rnew;
}

static request_rec *sub_req_method_uri(const char *method, const char *new_uri, const request_rec *r)
{
    request_rec *rnew;
    int res = HTTP_INTERNAL_SERVER_ERROR;
    rnew = make_sub_request(r);
    rnew->method = method; 
    rnew->method_number = ap_method_number_of(method);
    ap_parse_uri(rnew, new_uri);
    if (ap_is_recursion_limit_exceeded(r)) {
        rnew->status = HTTP_INTERNAL_SERVER_ERROR;
        return rnew;
    }
    ap_update_vhost_from_headers(rnew);
    if ((res = ap_process_request_internal(rnew))) {
        rnew->status = res;
    }
    return rnew;
}
/* end of copied code */


/* Look through 'Cookie' header for indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
static char *extract_cookie(request_rec *r, const char *szCookie_name) 
{
    const char *szRaw_cookie, *szRaw_cookie_start = NULL, *szRaw_cookie_end;
    char *szCookie = NULL;
    int i;

    /* get cookie string */
    szRaw_cookie = apr_table_get(r->headers_in, "Cookie");
    if (szRaw_cookie != NULL) {
        /* loop to search cookie name in cookie header */
        do {
            /* search cookie name in cookie string */
            if ((szRaw_cookie = strstr(szRaw_cookie, szCookie_name)) == NULL)
                return(szCookie);
            szRaw_cookie_start = szRaw_cookie;
            /* search '=' */
            if ((szRaw_cookie = strchr(szRaw_cookie, '=')) == NULL)
                return(szCookie);
        } while (strncmp(szCookie_name, szRaw_cookie_start, szRaw_cookie - szRaw_cookie_start) != 0);

        /* skip '=' */
        szRaw_cookie++;

        /* search end of cookie name value: ';' or end of cookie strings */
        szRaw_cookie_end = strchr(szRaw_cookie, ';');
        if (szRaw_cookie_end == NULL) {
            /* Must be the last cookie, so the end is the end of the string */
            szRaw_cookie_end = strchr(szRaw_cookie, '\0');
        }

        /* If both the first and last characters are double quotes then remove them */
        if ((*szRaw_cookie == '"') && (*(szRaw_cookie_end - 1) == '"') && ((szRaw_cookie_end - szRaw_cookie) > 1)) {
            /* Remove the quotes */
            szRaw_cookie++;
            szRaw_cookie_end--;
        }

        /* dup the value string found in apache pool and set the result pool ptr to szCookie ptr */
        char *szPotentialCookie = apr_pstrndup(r->pool, szRaw_cookie, szRaw_cookie_end-szRaw_cookie);
        if (szPotentialCookie != NULL) {
            /* unescape the value string */ 
            if (ap_unescape_url(szPotentialCookie) == 0) {
                /* be extra paranoid about the cookie value, reject if no md5sum */
                if (strlen(szPotentialCookie) == 32) {
                    szCookie = szPotentialCookie;
                    for (i = 0; i < 32; i++) {
                        if (!(((szCookie[i] >= '0') && (szCookie[i] <= '9')) || ((szCookie[i] >= 'a') && (szCookie[i] <= 'f')))) {
                            /* not a valid character */
                            szCookie = NULL;
                            /* Exit the loop */
                            i = 32;
                        }
                    }
                }
            }
        }
    }
    return(szCookie);
}

/* function to fix any headers in the input request that may be relied on by an
   application. e.g. php uses the Authorization header when logging the request
   in apache and not r->user (like it ought to). It is applied after the request
   has been authenticated. */
static void fix_headers_in(request_rec *r, const char *szPassword)
{
    const char *szUser = NULL;

    /* Set an Authorization header in the input request table for php and
       other applications that use it to obtain the username (mainly to fix
       apache logging of php scripts). We only set this if there is no header
       already present. */

    if (apr_table_get(r->headers_in, "Authorization") == NULL) {

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "fixing apache Authorization header for this request using user:%s",r->user);

        /* concat username and ':' */
        if (szPassword != NULL)
            szUser = apr_pstrcat(r->pool, r->user, ":", szPassword, NULL);
        else
            szUser = apr_pstrcat(r->pool, r->user, ":", NULL);

        /* alloc memory for the estimated encode size of the username */
        char *szB64_enc_user = apr_palloc(r->pool, apr_base64_encode_len(strlen(szUser)) + 1);
        if (!szB64_enc_user) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc failed!");
            return;
        }

        /* encode username in base64 format */
        apr_base64_encode(szB64_enc_user, szUser, strlen(szUser));

        /* set authorization header */
        apr_table_set(r->headers_in, "Authorization", apr_pstrcat(r->pool, "Basic ", szB64_enc_user, NULL));

        /* force auth type to basic */
        r->ap_auth_type = apr_pstrdup(r->pool, "Basic");
    }
  
    return;
} 

/* get session with szCookieValue key from memcached server */
static apr_table_t *get_session(request_rec *r, strAuth_memCookie_config_rec *conf, char *szCookieValue)
{
    char *szMemcached_addr = conf->szAuth_memCookie_memCached_addr.value;
    apr_time_t tExpireTime = conf->tAuth_memCookie_MemcacheObjectExpiry;

    memcached_st *mc_session = NULL;
    memcached_server_st *servers = NULL;
    memcached_return mc_err = 0;

    apr_table_t *pMySession = NULL;
    size_t nGetKeyLen = strlen(szCookieValue);
    uint32_t nGetFlags = 0;
    size_t nGetLen = 0;
    char *szTokenPos;
    char *szFieldTokenPos;
    char *szField;
    char *szValue;
    char *szFieldName;
    char *szFieldValue;
    char *szMyValue;
    const char *UserName;
    int nbInfo = 0;
    
    if ((pMySession = apr_table_make(r->pool, conf->nAuth_memCookie_SessionTableSize.value)) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_tablemake failed");
        return NULL;
    }

    /* init memcache lib */
    if ((mc_session = memcached_create(NULL)) == 0) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memcache lib init failed");
         return NULL;
    }
    servers = memcached_servers_parse(szMemcached_addr);
    memcached_server_push(mc_session, servers);

    if ((szValue = memcached_get(mc_session, szCookieValue, nGetKeyLen, &nGetLen, &nGetFlags, &mc_err)) == 0) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "memcached_get failed to find key '%s'",szCookieValue);
        memcached_free(mc_session);
        return NULL;
    }

    /* dup szValue in pool */
    szMyValue = apr_pstrdup(r->pool, szValue);

    /* split szValue into struct strAuthSession */
    /* szValue is formated multi line (\r\n) with name=value on each line */
    /* must containe UserName,Groups,RemoteIP fieldname */
    szTokenPos = NULL;
    for (szField = strtok_r(szMyValue, "\r\n", &szTokenPos); szField; szField=strtok_r(NULL, "\r\n", &szTokenPos)) {
        szFieldTokenPos = NULL;
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session field:%s",szField);
        szFieldName = strtok_r(szField, "=", &szFieldTokenPos);
        szFieldValue = strtok_r(NULL, "=", &szFieldTokenPos);
        if (szFieldName != NULL && szFieldValue != NULL) {
            /* add key and value in pMySession table */
            apr_table_set(pMySession, szFieldName, szFieldValue);
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session information %s=%s",szFieldName,szFieldValue);

            /* count the number of element added to table to check table size not reached */
            nbInfo++;
            if (nbInfo > conf->nAuth_memCookie_SessionTableSize.value) {
                ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "maximum session information reached!");
                if (szValue)
                    free(szValue);
                memcached_free(mc_session);
                return NULL;
            }
        }
    }

    if (!apr_table_get(pMySession, "UserName")) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Username not found in Session value(key:%s) found = %s",szCookieValue,szValue);
        pMySession = NULL;
    } else if ((conf->nAuth_memCookie_MatchIP_Mode.value != IP_MATCH_NOT_SET) && !apr_table_get(pMySession, "RemoteIP")) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "MatchIP_Mode activated and RemoteIP not found in Session value(key:%s) found = %s",szCookieValue,szValue);
        pMySession = NULL;
    } else {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Value for Session (key:%s) found => Username=%s Groups=%s RemoteIp=%s",
                                 szCookieValue,
                                 apr_table_get(pMySession,"UserName"),
                                 apr_table_get(pMySession,"Groups"),
                                 apr_table_get(pMySession,"RemoteIP"));
    }

    /* reset expire time */
    if (conf->nAuth_memCookie_MemcacheObjectExpiryReset.value && pMySession) {
        if ((mc_err = memcached_set(mc_session, szCookieValue, nGetKeyLen, szValue, nGetLen, tExpireTime, 0))) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,ERRTAG  "Expire time with mc_set (key:%s) failed with errcode=%d",szCookieValue,mc_err);
            pMySession = NULL;
        }
    }

    /* free returned value */
    if (szValue)
        free(szValue);

    /* free the mc session */
    memcached_free(mc_session);
    
    /* set the good username found in request structure */
    UserName = 0;
    if (pMySession != NULL)
        UserName = apr_table_get(pMySession, "UserName");
    if (UserName)
        r->user = (char *)UserName;

    return pMySession;
}


struct session_concat_func_data {
    apr_pool_t *pool;
    char *str;
};

static int session_concat_func(void *req, const char *key, const char *value) {
    struct session_concat_func_data *fd = req;
    if (strchr(key, '\r') || strchr(key, '\n'))
        return 1;
    if (strchr(value, '\r') || strchr(value, '\n'))
        return 1;
    fd->str = apr_pstrcat(fd->pool, fd->str, key, "=", value, "\r\n", NULL);
    return 1;
}

/* store session with szCookieValue key into the memcached server */
static int set_session(request_rec *r, strAuth_memCookie_config_rec *conf, char *szCookieValue, apr_table_t *session)
{
    char *szMemcached_addr = conf->szAuth_memCookie_memCached_addr.value;
    memcached_st *mc_session = NULL;
    memcached_server_st *servers = NULL;
    memcached_return mc_err = 0;
    size_t nGetKeyLen = strlen(szCookieValue);
    apr_time_t tExpireTime = conf->tAuth_memCookie_MemcacheObjectExpiry;
    struct session_concat_func_data fd;

    /* concat everything from the session into a single string */
    fd.pool = r->pool;
    fd.str = apr_pstrcat(r->pool, "", NULL);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "concat session...");
    apr_table_do(session_concat_func, &fd, session, NULL);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "-> %s", fd.str);

    /* put concatenated session into the memcachd */
    if ((mc_session = memcached_create(NULL)) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memcache lib init failed");
        return DECLINED;
    }
    servers = memcached_servers_parse(szMemcached_addr);
    memcached_server_push(mc_session, servers);
    if ((mc_err = memcached_set(mc_session, szCookieValue, nGetKeyLen, fd.str, strlen(fd.str), tExpireTime, 0))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,ERRTAG  "set_session memcached_set (key:%s) failed with errcode=%d",szCookieValue,mc_err);
        memcached_free(mc_session);
        return DECLINED;
    }
    memcached_free(mc_session);

    return OK;
}

/* delete session with szCookieValue key from the memcached server */
static int delete_session(request_rec *r, strAuth_memCookie_config_rec *conf, char *szCookieValue)
{
    char *szMemcached_addr=conf->szAuth_memCookie_memCached_addr.value;
    memcached_st *mc_session=NULL;
    memcached_server_st *servers = NULL;
    memcached_return mc_err=0;
    size_t nGetKeyLen=strlen(szCookieValue);

    if ((mc_session = memcached_create(NULL)) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memcache lib init failed");
        return DECLINED;
    }
    servers = memcached_servers_parse(szMemcached_addr);
    memcached_server_push(mc_session, servers);
    if ((mc_err = memcached_delete(mc_session, szCookieValue, nGetKeyLen, (time_t)0)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,ERRTAG  "delete_session memcached_delete (key:%s) failed with errcode=%d",szCookieValue,mc_err);
        memcached_free(mc_session);
        return DECLINED;
    }
    memcached_free(mc_session);
    return OK;
}

/* generate a random cookie */
static char *create_new_cookie(request_rec *r, char *username)
{
    apr_md5_ctx_t context;
    unsigned char digest[16];

    char digest_hex[33];
    unsigned char random[16];
    struct timeval tv;
    int i;

    gettimeofday(&tv, 0);
    apr_generate_random_bytes(random, 16);

    apr_md5_init(&context);
    apr_md5_update(&context, (const unsigned char *)random, sizeof(random));
    if (username)
        apr_md5_update(&context, (const unsigned char *)username, strlen(username));
    apr_md5_update(&context, (const unsigned char *)&tv, sizeof(tv));
    apr_md5_final(digest, &context);
    for (i = 0; i < 16; i++) {
        digest_hex[2 * i + 0] = "0123456789abcdef"[digest[i] >> 4 & 15];
        digest_hex[2 * i + 1] = "0123456789abcdef"[digest[i]      & 15];
    }
    digest_hex[32] = 0;
    return apr_pstrdup(r->pool, digest_hex);
}

/* check if szGroup are in szGroups. */
static int get_grp(request_rec *r, const char *szGroup, const char *szGroups)
{
    char *szGrp_End;
    char *szGrp_Pos;
    char *szMyGroups;
    int result = DECLINED;

    /* Only do something if we do actually have a group */
    if ((szGroups != NULL) && (szGroup != NULL) && (*szGroup != '\0')) {
        /* make a copy */
        szMyGroups = apr_pstrdup(r->pool, szGroups);
        /* search group in groups */
        if ((szGrp_Pos = strstr(szMyGroups, szGroup)) > 0) {
            /* search the next ':' and set '\0' in place of ':' */
            if ((szGrp_End = strchr(szGrp_Pos,':'))) {
                szGrp_End[0] = '\0';
            }

            /* compar szGroup with szGrp_Pos if ok return ok */
            if (!strcmp(szGroup, szGrp_Pos)) {
                result = OK;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "group found=%s",szGrp_Pos);
            }
        }
    }
    return(result);
}


/* user apr_table_do to set session information in child environment variable */
static int DoSetEnv(void *rec, const char *szKey, const char *szValue)
{
    request_rec *r = (request_rec*)rec;
    char *szEnvName = apr_pstrcat(r->pool,"MCAC_",szKey,NULL);
    /* set env var MCAC_USER to the user session value */
    apr_table_setn(r->subprocess_env, szEnvName, szValue);
    return 1;
}

/* user apr_table_do to set session information in header http */
static int doSetHeader(void *rec, const char *szKey, const char *szValue)
{
    strAuth_memCookie_config_rec *conf = NULL;
    request_rec *r = (request_rec*)rec;
    const char *szHeaderName = szKey;
    /* if key does not start with X-, preprent X-MCAC_ */
    if (strncasecmp(szHeaderName, "x-", 2) != 0)
        szHeaderName = apr_pstrcat(r->pool, "X-MCAC_", szHeaderName, NULL);

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    if (conf->nAuth_memCookie_SetSessionHTTPHeaderEncode.value) {
        /* alloc memory for the estimated encode size of the string */
        char *szB64_enc_string = apr_palloc(r->pool,apr_base64_encode_len(strlen(szValue))+1);
        if (!szB64_enc_string) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc for encoding http header failed!");
            return 0;
        }

        /* encode string in base64 format */
        apr_base64_encode(szB64_enc_string, szValue, strlen(szValue));

        /* set string header */
        apr_table_set(r->headers_in,szHeaderName, szB64_enc_string);
    } else {
        /* set string header */
        apr_table_set(r->headers_in,szHeaderName, szValue);
    }
    return 1;
}

/* create a session by doing a subrequest to URI uri, the returned headers define the session */
static apr_table_t *session_from_subrequest(request_rec *r, strAuth_memCookie_config_rec *conf, char *uri)
{
    apr_table_t *pAuthSession = NULL;
    request_rec *rr = NULL;
    const char *UserName;

    if (uri[0] == '/')
        rr = ap_sub_req_lookup_uri(uri, r, NULL);
    else
        rr = sub_req_method_uri("GET", uri, r);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "subrequest return1: %d", rr->status);

    if (!conf->nAuth_memCookie_AuthentificationURIOnlyAuth.value && rr->status == HTTP_OK) {
        /* need to add the "SINK" output filter, otherwise the response will be sent to the client */
        ap_add_output_filter("MEMCOOKIE_SINK", NULL, rr, rr->connection);

        if (ap_run_sub_req(rr) != OK) {
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "ap_run_sub_req error");
            ap_destroy_sub_req(rr);
            return 0;
        }
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "subrequest return2: %d", rr->status);
    }

    if (rr->status != HTTP_OK) {
        const char *www_auth = apr_table_get(rr->err_headers_out, "WWW-Authenticate");
        if (!www_auth) {
            www_auth = apr_table_get(rr->headers_out, "WWW-Authenticate");
        }
        if (www_auth) {
            apr_table_set(r->headers_out, "WWW-Authenticate", www_auth);
            apr_table_set(r->err_headers_out, "WWW-Authenticate", www_auth);
        }
        ap_destroy_sub_req(rr);
        return 0;
    }

    /* create session */
    if (!(pAuthSession = apr_table_make(r->pool, conf->nAuth_memCookie_SessionTableSize.value))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_tablemake failed");
        ap_destroy_sub_req(rr);
        return 0;
    } 
    
    /* copy all configured headers into the session */
    if (conf->szAuth_memCookie_SessionHeaders.value) {
        char *headers = apr_pstrdup(r->pool, conf->szAuth_memCookie_SessionHeaders.value);
        char *key, *keypos = 0;
        for(key = strtok_r(headers, ", ", &keypos); key; key = strtok_r(NULL, ", ", &keypos)) {
            const char *value;
            if (conf->nAuth_memCookie_AuthentificationURIOnlyAuth.value) {
                value = apr_table_get(rr->headers_in, key);
            } else {
                value = apr_table_get(rr->err_headers_out, key);
                if (!value)
                    value = apr_table_get(rr->headers_out, key);
            }
            if (value && !strchr(value, '\r') && !strchr(value, '\n')) {
                if (!strncmp(key, "X-MCAC_", 7))
                    apr_table_set(pAuthSession, key + 7, value);
                else
                    apr_table_set(pAuthSession, key, value);
            }
        }
    }

    /* copy the username into the session */
    if (conf->szAuth_memCookie_AuthentificationHeader.value) {
        if (conf->nAuth_memCookie_AuthentificationURIOnlyAuth.value) {
            UserName = apr_table_get(rr->headers_in, conf->szAuth_memCookie_AuthentificationHeader.value);
        } else {
            UserName = apr_table_get(rr->err_headers_out, conf->szAuth_memCookie_AuthentificationHeader.value);
            if (!UserName)
                UserName = apr_table_get(rr->headers_out, conf->szAuth_memCookie_AuthentificationHeader.value);
        }
        if (UserName && (strchr(UserName, '\r') != 0 || strchr(UserName, '\n') != 0))
            UserName = 0;
        if (UserName)
            apr_table_set(pAuthSession, "UserName", UserName);
        else
            apr_table_unset(pAuthSession, "UserName");
    }

    ap_destroy_sub_req(rr);

    /* make sure that we have a UserName */
    UserName = apr_table_get(pAuthSession, "UserName");
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "username: %s", UserName ? UserName : "NULL");
    if (!UserName)
        return 0;

    r->user = (char *)UserName;

    return pAuthSession;
}

/**************************************************
 * authentification phase: 
 * verify if cookie is set and if it is known in memcache server 
 **************************************************/
static int check_cookie_real1(strAuth_memCookie_config_rec *conf, request_rec *r)
{
    char *szCookieValue = NULL;
    apr_table_t *pAuthSession = NULL;
    apr_status_t tRetStatus;
    const char *command = NULL;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "ap_hook_check_user_id in");

    if (strncmp("Cookie", ap_auth_type(r), 6) != 0) {
        return HTTP_UNAUTHORIZED;
    }

    if (!conf->nAuth_memCookie_Authoritative.value)
        return DECLINED;

    if (!conf->szAuth_memCookie_CookieName.value) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_memCookie_CookieName specified");
        return HTTP_UNAUTHORIZED;
    }

    if (!conf->szAuth_memCookie_memCached_addr.value) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_memCookie_Memcached_AddrPort specified");
        return HTTP_UNAUTHORIZED;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "Memcached server(s) adresse(s) are %s",conf->szAuth_memCookie_memCached_addr.value);

    pAuthSession = NULL;

    /* extract session cookie from headers */
    szCookieValue = extract_cookie(r, conf->szAuth_memCookie_CookieName.value);

    /* if we have a cookie, get session from memcache */
    if (szCookieValue) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "got cookie; value is %s", szCookieValue);
        if((pAuthSession = get_session(r, conf, szCookieValue)) == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "AuthSession %s not found: %s", szCookieValue, r->filename);
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "cookie not found! not authorized!");
    }

    /* unset headers sent by the client that are supposed to be set by us */
    if (conf->szAuth_memCookie_AuthentificationHeader.value)
        apr_table_unset(r->headers_in, conf->szAuth_memCookie_AuthentificationHeader.value);
    if (conf->szAuth_memCookie_SessionHeaders.value) {
        char *headers = apr_pstrdup(r->pool, conf->szAuth_memCookie_SessionHeaders.value);
        char *key, *keypos = 0;
        for(key = strtok_r(headers, ", ", &keypos); key; key = strtok_r(NULL, ", ", &keypos))
            apr_table_unset(r->headers_in, key);
    }

    /* check for a login/logout command */
    if (conf->szAuth_memCookie_CommandHeader.value) {
        command = apr_table_get(r->headers_in, conf->szAuth_memCookie_CommandHeader.value);
        if (command && !strcasecmp(conf->szAuth_memCookie_CommandHeader.value, "Authorization")) {
            /* deduce command from authorization header */
            if (!*command)
                command = "logout";
            else
                command = "login";
        }
    }

   /* check if this is a logout request */
    if (szCookieValue && command && !strcasecmp(command, "logout")) {
        char *set_cookie;
        ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "deleting session %s", szCookieValue);

        /* add set-cookie directive to headers */
        set_cookie = apr_psprintf(r->pool, "%s=; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/", conf->szAuth_memCookie_CookieName.value);
        if (conf->szAuth_memCookie_CookieDomain.value && *conf->szAuth_memCookie_CookieDomain.value)
            set_cookie = apr_psprintf(r->pool, "%s; domain=%s", set_cookie, conf->szAuth_memCookie_CookieDomain.value);
        apr_table_add(r->headers_out, "Set-Cookie", set_cookie);
        apr_table_add(r->err_headers_out, "Set-Cookie", set_cookie);

        /* delete session from memcache */
        delete_session(r, conf, szCookieValue);
        return HTTP_UNAUTHORIZED;
    }

    /* we're ok if we have no session and anonymous access is allowed */
    /* (we ignore this if a "login" command is done to enforce a session) */
    if (!pAuthSession && conf->nAuth_memCookie_AllowAnonymous.value && !(command && !strcasecmp(command, "login")))
        return OK;

    /* if we have no session but a subrequest creation uri is configured, do the subrequest */
    if (!pAuthSession && conf->szAuth_memCookie_AuthentificationURI.value && *conf->szAuth_memCookie_AuthentificationURI.value) {
        char *set_cookie;

        pAuthSession = session_from_subrequest(r, conf, conf->szAuth_memCookie_AuthentificationURI.value);
        if (!pAuthSession) {
            return HTTP_UNAUTHORIZED;
        }

        /* create a new session cookie */
        szCookieValue = create_new_cookie(r, r->user);

        /* add set-cookie directive to headers */
        set_cookie = apr_psprintf(r->pool, "%s=%s; path=/; Max-Age=86400; Secure; HttpOnly", conf->szAuth_memCookie_CookieName.value, szCookieValue);
        if (conf->szAuth_memCookie_CookieDomain.value && *conf->szAuth_memCookie_CookieDomain.value)
            set_cookie = apr_psprintf(r->pool, "%s; domain=%s", set_cookie, conf->szAuth_memCookie_CookieDomain.value);
        apr_table_add(r->headers_out, "Set-Cookie", set_cookie);

        /* store new session into memcache */
        ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO, 0,r,ERRTAG  "creating new session in memcache");
        set_session(r, conf, szCookieValue, pAuthSession);
    }

    /* still no session? goodbye */
    if (!pAuthSession) {
        return HTTP_UNAUTHORIZED;
    }

    /* push session returned structure in request pool so we can access it in Auth_memCookie_check_auth() */
    if ((tRetStatus = apr_pool_userdata_setn(pAuthSession, "SESSION", NULL, r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "apr_pool_userdata_setn Apr Error: %d", tRetStatus);
        return HTTP_UNAUTHORIZED;
    }

    /* check remote ip if option is enabled */
    if (conf->nAuth_memCookie_MatchIP_Mode.value != IP_MATCH_NOT_SET) {
        char *szRemoteIP = NULL;
        const char *szPotentialIP = NULL;

        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "check MatchIP_Mode:%d",conf->nAuth_memCookie_MatchIP_Mode.value);
        switch (conf->nAuth_memCookie_MatchIP_Mode.value) {
            case IP_MATCH_VIA:
                szPotentialIP = apr_table_get(r->headers_in, "Via");
                break;

            case IP_MATCH_X_FORWARDED:
                szPotentialIP = apr_table_get(r->headers_in, "X-Forwarded-For");
                break;

            case IP_MATCH_CLIENT_IP:
                szPotentialIP = apr_table_get(r->headers_in, "Client-IP");
                break;

            case IP_MATCH_CLIENT_IP_X_FORWARDED:
                /* First look at client IP then X-Forward-For */
                szPotentialIP = apr_table_get(r->headers_in, "Client-IP");
                if (szPotentialIP == NULL) {
                    szPotentialIP = apr_table_get(r->headers_in, "X-Forwarded-For");
                }
                break;
        }

        if (szPotentialIP != NULL) {
            szRemoteIP = apr_pstrdup(r->pool, szPotentialIP);
        } else {
            szRemoteIP = apr_pstrdup(r->pool, r->connection->client_ip);
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "check ip: remote_ip=%s cookie_ip=%s", szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
        if (strcmp(szRemoteIP, apr_table_get(pAuthSession,"RemoteIP"))) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "unauthorized, by ip. user:%s remote_ip:%s != cookie_ip:%s", apr_table_get(pAuthSession,"UserName"),szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
            return HTTP_UNAUTHORIZED;
        }
    }

    /* set env var MCAC_ to the information session value */
    apr_table_do(DoSetEnv, r, pAuthSession, NULL);

    /* set REMOTE_USER var for scripts language */
    apr_table_setn(r->subprocess_env, "REMOTE_USER", apr_table_get(pAuthSession,"UserName"));

    /* set MCAC-SESSIONKEY var for scripts language */
    apr_table_setn(r->subprocess_env, "MCAC_SESSIONKEY", szCookieValue);
    
    /* set in http header the session value */
    if (conf->nAuth_memCookie_SetSessionHTTPHeader.value)
        apr_table_do(doSetHeader, r, pAuthSession, NULL);

    /* log authorisation ok */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "authentication ok");

    /* fix http header for php */
    if (conf->nAuth_memCookie_authbasicfix.value)
        fix_headers_in(r, apr_table_get(pAuthSession, "Password"));

    /* if all is ok return auth ok */
    return OK;
}

static strAuth_memCookie_config_rec *getConfig(request_rec *r) {
    return(ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module));
}

static bool checkRedirect(strAuth_memCookie_config_rec *conf, request_rec *r) {
    bool redirected = false;

    if (conf->szAuth_memCookie_RedirectURLOnFailure.value && ap_strchr_c(conf->szAuth_memCookie_RedirectURLOnFailure.value, ':')) {
        apr_table_setn(r->err_headers_out, "Location", conf->szAuth_memCookie_RedirectURLOnFailure.value);
        redirected = true;
    }
    return(redirected);
}

static int Auth_memCookie_check_cookie(request_rec *r) {
    strAuth_memCookie_config_rec *conf = getConfig(r);
    int result = check_cookie_real1(conf, r);

    if (result == HTTP_UNAUTHORIZED) {
        if (checkRedirect(conf, r)) {
            result = HTTP_TEMPORARY_REDIRECT;
        }
    }
    return(result);
}

/**************************************************
 * authentification phase: 
 * Checking authoriszation for user and group of the authenticated cookie 
 **************************************************/

static int Auth_memCookie_check_auth(request_rec *r) {
    strAuth_memCookie_config_rec *conf=NULL;
    char *szMyUser = r->user;
    int m = r->method_number;

    const apr_array_header_t *reqs_arr=NULL;
    require_line *reqs=NULL;

    register int x;
    const char *szRequireLine;
    char *szRequire_cmd;

    apr_table_t *pAuthSession=NULL;
    apr_status_t tRetStatus;

    /* If no require lines, we assume they are authorised */
    bool bAuthorised = true;

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    /* check if module are authoritative and we are cookie authenticating*/
    if (!conf->nAuth_memCookie_Authoritative.value) {
        return DECLINED;
    }

    if ((tRetStatus = apr_pool_userdata_get((void**)&pAuthSession, "SESSION", r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,ERRTAG "apr_pool_userdata_get Apr Error: %d", tRetStatus);
        return HTTP_FORBIDDEN;
    }

    /* Even though the status above was successful, we still might not have a session, so an extra check is required */
    if (pAuthSession == NULL) {
        /* We do not appear to have a session, so get out of here before we crash */
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,ERRTAG "pAuthSession is null");
        return HTTP_FORBIDDEN;
    }

    /* get require line */
    reqs_arr = conf->requireelems;
    reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    /* decline if no require line found */
    if (!reqs_arr) {
        return DECLINED;
    }

    /* walk throug the array to check each require command */
    /* All require items must be met ... */
    for (x = 0; x < reqs_arr->nelts; x++ && bAuthorised) {

/* Not overly certain of the purpose of this, but it stops it all working
/*        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
/*            continue;
*/
        /* get require line */
        szRequireLine = reqs[x].requirement;

        /* get the first word in require line */
        szRequire_cmd = ap_getword_white(r->pool, &szRequireLine);

        /* if require cmd are valid-user, they are already authenticated than allow and return OK */
        if (!strcmp("valid-user",szRequire_cmd)) {
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Require Cmd valid-user");
        } else if (!strcmp("user", szRequire_cmd)) {
            /* check the required user */ 
            bool bUserFound = false;
            /* we need to loop through all the users in the require and see if we match one */
            for (char *szUser = ap_getword_white(r->pool, &szRequireLine); (szUser != NULL) && (*szUser != '\0') && !bUserFound; szUser = ap_getword_white(r->pool, &szRequireLine)) {
                if (!strcmp(szMyUser, szUser)) {
                    bUserFound = true;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "the user logged '%s' is authorized", szMyUser);
                }
            }

            /* Did we find a user */
            if (!bUserFound) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, ERRTAG  "the user logged '%s' is not the user required", szMyUser);
                bAuthorised = false;
            }
        } else if (!strcmp("group", szRequire_cmd)) {
            bool bGroupFound = false;
            const char *szGroups = apr_table_get(pAuthSession, "Groups");
            if (szGroups != NULL) { 
                /* we need to loop through all the groups in the require and see if we match one */
                for (char *szGroup = ap_getword_white(r->pool, &szRequireLine); (szGroup != NULL) && (*szGroup != '\0') && !bGroupFound; szGroup = ap_getword_white(r->pool, &szRequireLine)) {
                    if (get_grp(r, szGroup, szGroups) == OK) {
                        bGroupFound = true;
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "the user logged '%s' as the good group %s and is authorized", szMyUser, szGroup);
                    }
                }
            }

            /* Did we find a group */
            if (!bGroupFound) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, ERRTAG  "user %s not in group", szMyUser);
                bAuthorised = false;
            }
        }
    }

    /* Back door way to authorise a base path */
    /* Originally added as I struggled with the apache config as it always came in here, but I worked out what I was doing wrong */
    /* so this if block can probably be removed, along with the config setting Auth_memCookie_AcceptPathStart */
    if (!bAuthorised) {
        if (conf->szAuth_memCookie_AcceptPathStart.value != NULL) {
            /* Note: We ignore the GET */
            if (!strncmp(r->the_request + 4, conf->szAuth_memCookie_AcceptPathStart.value, strlen(conf->szAuth_memCookie_AcceptPathStart.value))) {
                bAuthorised = true;
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG  "Request matched AcceptPathStart");
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "the user logged '%s' is %s authorized, request: %s", szMyUser, (bAuthorised ? "" : "not"), r->the_request);
    return(bAuthorised ? OK : HTTP_FORBIDDEN);
}


static int memcookie_sink_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    return APR_SUCCESS;
}

/**************************************************
 * register module hook 
 **************************************************/
static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("MEMCOOKIE_SINK", memcookie_sink_filter, NULL, AP_FTYPE_CONTENT_SET + 1);
    ap_hook_check_authn(Auth_memCookie_check_cookie, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
/*    ap_hook_check_user_id(Auth_memCookie_check_cookie, NULL, NULL, APR_HOOK_MIDDLE);
*/

/* Old Variant
    ap_hook_auth_checker(Auth_memCookie_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
*/
/* Possibly new 2.4 equivalent
*/
    ap_hook_check_authz(Auth_memCookie_check_auth, NULL,NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

/************************************************************************************
 *  Apache CONFIG Phase:
 ************************************************************************************/

static void setStringSetting(apr_pool_t *pMemoryPool, strConfigSetting *pSetting, const char *pValue, bool defaultValue) {
    if (pSetting != NULL) {
        char *pAllocatedValue = NULL;
        if (pValue != NULL) {
            pAllocatedValue = apr_pstrdup(pMemoryPool, pValue);
        }
        pSetting->value = pAllocatedValue;
        pSetting->isSet = !defaultValue;
    }
}

static void setStringDefault(apr_pool_t *pMemoryPool, strConfigSetting *pSetting, const char *pValue) {
    setStringSetting(pMemoryPool, pSetting, pValue, true);
}

static void setString(cmd_parms *pCommand, strConfigSetting *pSetting, const char *pValue) {
    setStringSetting(pCommand->pool, pSetting, pValue, false);
}

static void mergeString(apr_pool_t *pMemoryPool, strConfigSetting *pDestination, strConfigSetting *pBase, strConfigSetting *pAdditional) {
    pDestination->value = ((pAdditional->isSet) ? pAdditional->value : pBase->value);
    pDestination->isSet = (pAdditional->isSet || pBase->isSet);
}

static void setIntSetting(intConfigSetting *pSetting, int value, bool defaultValue) {
    if (pSetting != NULL) {
        pSetting->value = value;
        pSetting->isSet = !defaultValue;
    }
}

static void setIntDefault(intConfigSetting *pSetting, int value) {
    setIntSetting(pSetting, value, true);
}

static void setInt(intConfigSetting *pSetting, int value) {
    setIntSetting(pSetting, value, false);
}

static void setIntString(intConfigSetting *pSetting, const char *pValue) {
    if (pValue != NULL) {
        int value = atoi(pValue);
        setInt(pSetting, value);
    }
}

static void mergeInt(intConfigSetting *pDestination, intConfigSetting *pBase, intConfigSetting *pAdditional) {
    pDestination->value = ((pAdditional->isSet) ? pAdditional->value : pBase->value);
    pDestination->isSet = (pAdditional->isSet || pBase->isSet);
}

static const char *setMemCached_addr(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_memCached_addr, pValue);
    return(NULL);
}

static const char *setCookieName(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_CookieName, pValue);
    return(NULL);
}

static const char *setCookieDomain(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_CookieDomain, pValue);
    return(NULL);
}

static const char *setMemcacheObjectExpiryReset(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_MemcacheObjectExpiryReset, value);
    return(NULL);
}

static const char *setGroupAuthoritative(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_GroupAuthoritative, value);
    return(NULL);
}

static const char *setAuthoritative(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_Authoritative, value);
    return(NULL);
}

static const char *setAuthbasicfix(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_authbasicfix, value);
    return(NULL);
}

static const char *setSessionHTTPHeader(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_SetSessionHTTPHeader, value);
    return(NULL);
}

static const char *setSessionHTTPHeaderEncode(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_SetSessionHTTPHeaderEncode, value);
    return(NULL);
}

static const char *setSessionTableSize(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setIntString(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_SessionTableSize, pValue);
    return(NULL);
}

static const char *setAuthentificationURI(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_AuthentificationURI, pValue);
    return(NULL);
}

static const char *setAuthentificationHeader(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_AuthentificationHeader, pValue);
    return(NULL);
}

static const char *setSessionHeaders(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_SessionHeaders, pValue);
    return(NULL);
}

static const char *setCommandHeader(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_CommandHeader, pValue);
    return(NULL);
}

static const char *setAllowAnonymous(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_AllowAnonymous, value);
    return(NULL);
}

static const char *setAuthentificationURIOnlyAuth(cmd_parms *pCommand, void *pConfig, int value) {
    setInt(&((strAuth_memCookie_config_rec *)pConfig)->nAuth_memCookie_AuthentificationURIOnlyAuth, value);
    return(NULL);
}

static const char *setRedirectURLOnFailure(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_RedirectURLOnFailure, pValue);
    return(NULL);
}

static const char *setAcceptPathStart(cmd_parms *pCommand, void *pConfig, const char *pValue) {
    setString(pCommand, &((strAuth_memCookie_config_rec *)pConfig)->szAuth_memCookie_AcceptPathStart, pValue);
    return(NULL);
}

static void *merge_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    strAuth_memCookie_config_rec *new = (strAuth_memCookie_config_rec *) apr_pcalloc(p, sizeof(strAuth_memCookie_config_rec));
    strAuth_memCookie_config_rec *add = (strAuth_memCookie_config_rec *) addv;
    strAuth_memCookie_config_rec *base = (strAuth_memCookie_config_rec *) basev;

    mergeString(p, &new->szAuth_memCookie_memCached_addr, &base->szAuth_memCookie_memCached_addr, &add->szAuth_memCookie_memCached_addr);
    mergeString(p, &new->szAuth_memCookie_CookieName, &base->szAuth_memCookie_CookieName, &add->szAuth_memCookie_CookieName);
    mergeString(p, &new->szAuth_memCookie_CookieDomain, &base->szAuth_memCookie_CookieDomain, &add->szAuth_memCookie_CookieDomain);
    mergeInt(&new->nAuth_memCookie_MemcacheObjectExpiryReset, &base->nAuth_memCookie_MemcacheObjectExpiryReset, &add->nAuth_memCookie_MemcacheObjectExpiryReset);
    mergeInt(&new->nAuth_memCookie_MatchIP_Mode, &base->nAuth_memCookie_MatchIP_Mode, &add->nAuth_memCookie_MatchIP_Mode);
    mergeInt(&new->nAuth_memCookie_GroupAuthoritative, &base->nAuth_memCookie_GroupAuthoritative, &add->nAuth_memCookie_GroupAuthoritative);
    mergeInt(&new->nAuth_memCookie_Authoritative, &base->nAuth_memCookie_Authoritative, &add->nAuth_memCookie_Authoritative);
    mergeInt(&new->nAuth_memCookie_authbasicfix, &base->nAuth_memCookie_authbasicfix, &add->nAuth_memCookie_authbasicfix);
    mergeInt(&new->nAuth_memCookie_SetSessionHTTPHeader, &base->nAuth_memCookie_SetSessionHTTPHeader, &add->nAuth_memCookie_SetSessionHTTPHeader);
    mergeInt(&new->nAuth_memCookie_SetSessionHTTPHeaderEncode, &base->nAuth_memCookie_SetSessionHTTPHeaderEncode, &add->nAuth_memCookie_SetSessionHTTPHeaderEncode);
    mergeInt(&new->nAuth_memCookie_SessionTableSize, &base->nAuth_memCookie_SessionTableSize, &add->nAuth_memCookie_SessionTableSize);

    mergeString(p, &new->szAuth_memCookie_AuthentificationURI, &base->szAuth_memCookie_AuthentificationURI, &add->szAuth_memCookie_AuthentificationURI);
    mergeString(p, &new->szAuth_memCookie_AuthentificationHeader, &base->szAuth_memCookie_AuthentificationHeader, &add->szAuth_memCookie_AuthentificationHeader);
    mergeString(p, &new->szAuth_memCookie_SessionHeaders, &base->szAuth_memCookie_SessionHeaders, &add->szAuth_memCookie_SessionHeaders);
    mergeString(p, &new->szAuth_memCookie_CommandHeader, &base->szAuth_memCookie_CommandHeader, &add->szAuth_memCookie_CommandHeader);
    mergeInt(&new->nAuth_memCookie_AllowAnonymous, &base->nAuth_memCookie_AllowAnonymous, &add->nAuth_memCookie_AllowAnonymous);
    mergeInt(&new->nAuth_memCookie_AuthentificationURIOnlyAuth, &base->nAuth_memCookie_AuthentificationURIOnlyAuth, &add->nAuth_memCookie_AuthentificationURIOnlyAuth);
    mergeString(p, &new->szAuth_memCookie_AcceptPathStart, &base->szAuth_memCookie_AcceptPathStart, &add->szAuth_memCookie_AcceptPathStart);

    mergeString(p, &new->szAuth_memCookie_RedirectURLOnFailure, &base->szAuth_memCookie_RedirectURLOnFailure, &add->szAuth_memCookie_RedirectURLOnFailure);

    /* For the time being we will assume these 2 are set at the lowest level */
    new->tAuth_memCookie_MemcacheObjectExpiry = add->tAuth_memCookie_MemcacheObjectExpiry;
    new->requireelems = add->requireelems;
    return(new);
}

static void *create_dir_config(apr_pool_t *p, char *d)
{
    strAuth_memCookie_config_rec *conf = apr_palloc(p, sizeof(*conf));

    setStringDefault(p, &conf->szAuth_memCookie_memCached_addr, "127.0.0.1:11211");
    setStringDefault(p, &conf->szAuth_memCookie_CookieName, "AuthMemCookie");
    setStringDefault(p, &conf->szAuth_memCookie_CookieDomain, NULL);
    conf->tAuth_memCookie_MemcacheObjectExpiry = 3600; /* memcache object expire time, 1H by default */
    setIntDefault(&conf->nAuth_memCookie_MemcacheObjectExpiryReset, 1);   /* fortress is secure by default, reset object expire time in memcache by default */
    setIntDefault(&conf->nAuth_memCookie_MatchIP_Mode, IP_MATCH_NOT_SET);   /* method used in matchip, use (0) remote ip by default, if set to 1 for use ip from x_forwarded_for http header and 2 for use Via http header */
    setIntDefault(&conf->nAuth_memCookie_GroupAuthoritative, 1);  /* group are handled by this module by default */
    setIntDefault(&conf->nAuth_memCookie_Authoritative, 0);  /* not by default */
    setIntDefault(&conf->nAuth_memCookie_authbasicfix, 1);  /* fix header for php auth by default */
    setIntDefault(&conf->nAuth_memCookie_SetSessionHTTPHeader, 0); /* set session information in http header of authenticated user */
    setIntDefault(&conf->nAuth_memCookie_SetSessionHTTPHeaderEncode, 1); /* encode http header groups value by default */
    setIntDefault(&conf->nAuth_memCookie_SessionTableSize, 10); /* Max number of element in session information table, 10 by default */
    conf->requireelems=apr_array_make(p,20,sizeof(require_line));        

    setStringDefault(p, &conf->szAuth_memCookie_AuthentificationURI, NULL);
    setStringDefault(p, &conf->szAuth_memCookie_AuthentificationHeader, NULL);
    setStringDefault(p, &conf->szAuth_memCookie_SessionHeaders, NULL);
    setStringDefault(p, &conf->szAuth_memCookie_CommandHeader, NULL);
    setIntDefault(&conf->nAuth_memCookie_AllowAnonymous, 0);
    setIntDefault(&conf->nAuth_memCookie_AuthentificationURIOnlyAuth, 0);
    setStringDefault(p, &conf->szAuth_memCookie_AcceptPathStart, NULL);

    setStringDefault(p, &conf->szAuth_memCookie_RedirectURLOnFailure, NULL);
    return(conf);
}

static const char *cmd_MatchIP_Mode(cmd_parms *cmd, void *InDirConf, const char *p1) {
    strAuth_memCookie_config_rec *conf = (strAuth_memCookie_config_rec*)InDirConf;

    if ((strcasecmp("1", p1) == 0) || (strcasecmp("X-Forwarded-For", p1) == 0)) {
        setInt(&conf->nAuth_memCookie_MatchIP_Mode, IP_MATCH_X_FORWARDED);
    } else if ((strcasecmp("2", p1) == 0) || (strcasecmp("Via", p1) == 0)) {
        setInt(&conf->nAuth_memCookie_MatchIP_Mode, IP_MATCH_VIA);
    } else if ((strcasecmp("3", p1) == 0) || (strcasecmp("RemoteIP", p1) == 0)) {
        setInt(&conf->nAuth_memCookie_MatchIP_Mode, IP_MATCH_REMOTE);
    } else if ((strcasecmp("4", p1) == 0) || (strcasecmp("ClientIP", p1) == 0)) {
        setInt(&conf->nAuth_memCookie_MatchIP_Mode, IP_MATCH_CLIENT_IP);
    } else if ((strcasecmp("5", p1) == 0) || (strcasecmp("ClientIP-X-Forwarded-For", p1) == 0)) {
        setInt(&conf->nAuth_memCookie_MatchIP_Mode, IP_MATCH_CLIENT_IP_X_FORWARDED);
    } else {
        setInt(&conf->nAuth_memCookie_MatchIP_Mode, IP_MATCH_NOT_SET);
    }
    return NULL;
}

static const char* add_require_tag(cmd_parms *cmd, void *InDirConf, const char *p1) {
    strAuth_memCookie_config_rec *conf=(strAuth_memCookie_config_rec*)InDirConf;
    require_line *rt = apr_array_push(conf->requireelems);
    rt->requirement = (char*) p1;
    return NULL;
}

/* apache config fonction of the module */
static const command_rec cmds[] =
{
    AP_INIT_TAKE1("Auth_memCookie_Memcached_AddrPort", setMemCached_addr, NULL,
        OR_AUTHCFG, "ip or host adressei(s) and port (':' separed) of memcache(s) daemon to be used, coma separed"),

    AP_INIT_TAKE1("Auth_memCookie_Memcached_SessionObject_ExpireTime", ap_set_int_slot,
        (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, tAuth_memCookie_MemcacheObjectExpiry),
        OR_AUTHCFG, "Session object in memcached expiry time, in secondes."),

    AP_INIT_TAKE1("Auth_memCookie_SessionTableSize", setSessionTableSize, NULL,
        OR_AUTHCFG, "Max number of element in session information table. 10 by default"),

    AP_INIT_FLAG ("Auth_memCookie_Memcached_SessionObject_ExpiryReset", setMemcacheObjectExpiryReset, NULL,
        OR_AUTHCFG, "Set to 'no' to not reset object expiry time in memcache... yes by default"),

    AP_INIT_FLAG ("Auth_memCookie_SetSessionHTTPHeader", setSessionHTTPHeader, NULL,
        OR_AUTHCFG, "Set to 'yes' to set session information to http header of the authenticated users, no by default"),

    AP_INIT_FLAG ("Auth_memCookie_SetSessionHTTPHeaderEncode", setSessionHTTPHeaderEncode, NULL,
        OR_AUTHCFG, "Set to 'yes' to mime64 encode session information to http header, no by default"),

    AP_INIT_TAKE1("Auth_memCookie_CookieName", setCookieName, NULL,
        OR_AUTHCFG, "Name of cookie to set"),

    AP_INIT_TAKE1 ( "Auth_memCookie_MatchIP_Mode", cmd_MatchIP_Mode, NULL, 
        OR_AUTHCFG, "To check cookie ip adresse, Set to '1' to use 'X-Forwarded-For' http header, to '2' to use 'Via' http header, and to '3' to use apache remote_ip, '4' to use 'Client-IP' http header, '5' to use 'Client-IP' http header and then 'X-Forwarded-For' http header. set to '0' by default to desactivate the ip check."),

    AP_INIT_FLAG ("Auth_memCookie_GroupAuthoritative", setGroupAuthoritative, NULL,
        OR_AUTHCFG, "Set to 'no' to allow access control to be passed along to lower modules, for group acl check, set to 'yes' by default."),

    AP_INIT_FLAG ("Auth_memCookie_Authoritative", setAuthoritative, NULL,
        OR_AUTHCFG, "Set to 'yes' to allow access control to be passed along to lower modules, set to 'no' by default"),

    AP_INIT_FLAG ("Auth_memCookie_SilmulateAuthBasic", setAuthbasicfix, NULL,
        OR_AUTHCFG, "Set to 'no' to fix http header and auth_type for simulating auth basic for scripting language like php auth framework work, set to 'yes' by default"),

    AP_INIT_RAW_ARGS("Require", add_require_tag, NULL, OR_AUTHCFG,
                     "specifies require directive"
                     "which one must pass (or not) for a request to suceeed"),    

    AP_INIT_TAKE1("Auth_memCookie_AuthentificationURI", setAuthentificationURI, NULL,
        OR_AUTHCFG, "URL to use for authentification"),

    AP_INIT_FLAG ("Auth_memCookie_AuthentificationURIOnlyAuth", setAuthentificationURIOnlyAuth, NULL,
        OR_AUTHCFG, "Set to 'yes' if authentification checking is enough for AuthentificationURI"),

    AP_INIT_TAKE1("Auth_memCookie_AuthentificationHeader", setAuthentificationHeader, NULL,
        OR_AUTHCFG, "Header containing the Username"),

    AP_INIT_TAKE1("Auth_memCookie_CommandHeader", setCommandHeader, NULL,
        OR_AUTHCFG, "Header triggering session deletion"),

    AP_INIT_TAKE1("Auth_memCookie_SessionHeaders", setSessionHeaders, NULL,
        OR_AUTHCFG, "Comma seperated list of headers that define a session"),

    AP_INIT_TAKE1("Auth_memCookie_CookieDomain", setCookieDomain, NULL,
        OR_AUTHCFG, "Domain of cookie to set"),

    AP_INIT_FLAG ("Auth_memCookie_AllowAnonymous", setAllowAnonymous, NULL,
        OR_AUTHCFG, "Set to 'yes' to allow alonymous access if no session is found"),

    AP_INIT_TAKE1("Auth_memCookie_RedirectURLOnFailure", setRedirectURLOnFailure, NULL,
        OR_AUTHCFG, "URL to redirect to on authentication failure"),

    AP_INIT_TAKE1("Auth_memCookie_AcceptPathStart", setAcceptPathStart, NULL,
        OR_AUTHCFG, "URL to redirect to on authentication failure"),

    {NULL}
};

/* apache module structure */
AP_DECLARE_MODULE(mod_auth_memcookie) =
{
    STANDARD20_MODULE_STUFF,
    create_dir_config, /* dir config creater */
    merge_dir_config,  /* dir merger --- default is to override */
    NULL,              /* server config */
    NULL,              /* merge server config */
    cmds,              /* command apr_table_t */
    register_hooks     /* register hooks */
};
