#include "websocket_handler.h"
#include "http_handler.h"
#include "config.h"
#include "http_config.h"
#include "http_request.h"
#include "ap_config.h"
#include "mod_websocket_hook_export.h"
#include <string>

static int grpcbackend_handler(request_rec *r);
static int grpcbackend_fixups(request_rec *r);
static int grpcbackend_ws_plugin_init(const char* name, WebSocketPlugin** pluginptr);
static void grpcbackend_register_hooks(apr_pool_t *p);
static const char* grpcbackend_set_enabled(cmd_parms* cmd, void* cfg, const char* arg);
static const char* grpcbackend_set_host(cmd_parms* cmd, void* cfg, const char* arg);
static const char* grpcbackend_set_calltimeout(cmd_parms* cmd, void* cfg, const char* arg);
static const char* grpcbackend_set_connecttimeout(cmd_parms* cmd, void* cfg, const char* arg);
static void* grpcbackend_create_dir_conf(apr_pool_t* pool, char* context);
static void* grpcbackend_merge_dir_conf(apr_pool_t* pool, void* BASE, void* ADD);

static int is_websocket_upgrade(request_rec *r);

static const command_rec grpcbackend_directives[] = {
    AP_INIT_TAKE1("grpcEnabled", (cmd_func)grpcbackend_set_enabled, NULL, ACCESS_CONF | RSRC_CONF, "Enabled or disable mod_grpcbackend"),
    AP_INIT_TAKE1("grpcHost", (cmd_func)grpcbackend_set_host, NULL, ACCESS_CONF | RSRC_CONF, "Set GRPC Service host (and port)"),
    AP_INIT_TAKE1("grpcCallTimeout", (cmd_func)grpcbackend_set_calltimeout, NULL, ACCESS_CONF | RSRC_CONF, "Set call timeout"),
    AP_INIT_TAKE1("grpcConnectTimeout", (cmd_func)grpcbackend_set_connecttimeout, NULL, ACCESS_CONF | RSRC_CONF, "Set connect timeout"),
    { NULL }
};

extern "C" {
    /* Dispatch list for API hooks */
    AP_DECLARE_MODULE(grpcbackend) = {
        STANDARD20_MODULE_STUFF, 
        grpcbackend_create_dir_conf,/* create per-dir    config structures */
        grpcbackend_merge_dir_conf, /* merge  per-dir    config structures */
        NULL,                  /* create per-server config structures */
        NULL,                  /* merge  per-server config structures */
        grpcbackend_directives,     /* table of config file commands       */
        grpcbackend_register_hooks  /* register hooks                      */
    };
}

static int grpcbackend_handler(request_rec *r)
{
    if(strcmp(r->handler, "grpcbackend")) {
        return DECLINED;
    }
    auto* handler = http_handler::create(r->pool, r);
    if (!handler->get_config()->enabled) {
        return DECLINED;
    }
    return handler->handle_request();
}

static int grpcbackend_fixups(request_rec *r)
{
    // We relly on mod_websocket.c to handle websocket connections for us if a ws uri is registered with a grpc backend
    auto* config = static_cast<grpcbackend_config_t*>(ap_get_module_config(r->per_dir_config, &grpcbackend_module));
    if (config->enabled && !strcmp(r->handler, "grpcbackend") && is_websocket_upgrade(r)) {
        r->handler = apr_pstrdup(r->pool, "websocket-handler");
    }
    return DECLINED;
}

size_t CALLBACK grpcbackend_ws_onmessage(void *plugin_private, const WebSocketServer *server, const int type, unsigned char *buffer, const size_t buffer_size)
{
    auto* handler = reinterpret_cast<websocket_handler*>(plugin_private);
    handler->on_message(type, buffer, buffer_size);
    return 0;
}

void* CALLBACK grpcbackend_ws_onconnect(const WebSocketServer *server)
{
    auto* r = server->request(server);
    
    try {
        return websocket_handler::create(r->pool, server);
    }catch(const std::exception& e) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Failed to create ws handler: %s", e.what());
        return nullptr;
    }
}

void CALLBACK grpcbackend_ws_ondisconnect(void *plugin_private, const WebSocketServer *server)
{
    auto* handler = reinterpret_cast<websocket_handler*>(plugin_private);
    handler->on_disconnect();
}

static WebSocketPlugin grpcbackend_ws_plugin = {
    sizeof(WebSocketPlugin),
    WEBSOCKET_PLUGIN_VERSION_0,
    NULL, /* destroy */
    grpcbackend_ws_onconnect, /* connect */
    grpcbackend_ws_onmessage, /* onmessage */
    grpcbackend_ws_ondisconnect /* disconnect */
};

static int grpcbackend_ws_plugin_init(const char* name, WebSocketPlugin** pluginptr)
{
    if(!strcmp(name, "grpcbackend")) {
        *pluginptr = &grpcbackend_ws_plugin;
        return OK;
    }
    return DECLINED;
}

static void grpcbackend_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(grpcbackend_fixups, NULL, NULL, APR_HOOK_LAST);
    ap_hook_handler(grpcbackend_handler, NULL, NULL, APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(websocket_plugin_init, grpcbackend_ws_plugin_init, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char* grpcbackend_set_enabled(cmd_parms* cmd, void* cfg, const char* arg)
{
    auto* config = static_cast<grpcbackend_config_t*>(cfg);
    if(config) {
        config->enabled = !strcasecmp(arg, "on");
    }
    return nullptr;
}

static const char* grpcbackend_set_host(cmd_parms* cmd, void* cfg, const char* arg)
{
    auto* config = static_cast<grpcbackend_config_t*>(cfg);
    if(config) {
        config->host = apr_pstrdup(cmd->pool, arg);
    }
    return nullptr;
}

static const char* grpcbackend_set_calltimeout(cmd_parms* cmd, void* cfg, const char* arg)
{
    auto* config = static_cast<grpcbackend_config_t*>(cfg);
    if(config) {
        config->call_timeout_ms = std::stoll(arg);
        if(config->call_timeout_ms < 0)
            config->call_timeout_ms = 0;
    }
    return nullptr;
}

static const char* grpcbackend_set_connecttimeout(cmd_parms* cmd, void* cfg, const char* arg)
{
    auto* config = static_cast<grpcbackend_config_t*>(cfg);
    if(config) {
        config->connect_timeout_ms = std::stoll(arg);
        if(config->connect_timeout_ms < 0)
            config->connect_timeout_ms = 0;
    }
    return nullptr;
}

static void* grpcbackend_create_dir_conf(apr_pool_t* pool, char* context)
{
    auto* config = static_cast<grpcbackend_config_t*>(apr_pcalloc(pool, sizeof(grpcbackend_config_t)));

    if(config) {
        config->host = nullptr;
        config->enabled.initialized = false;
        config->call_timeout_ms = -1;
        config->connect_timeout_ms = -1;
    }

    return config;
}

static void* grpcbackend_merge_dir_conf(apr_pool_t* pool, void* BASE, void* ADD)
{
    auto* base = static_cast<grpcbackend_config_t*>(BASE);
    auto* add = static_cast<grpcbackend_config_t*>(ADD);
    auto* conf = static_cast<grpcbackend_config_t*>(grpcbackend_create_dir_conf(pool, nullptr));

    if(add->enabled.initialized) conf->enabled = add->enabled;
    else conf->enabled = base->enabled;
    
    conf->host = apr_pstrdup(pool, add->host?add->host:base->host);
    conf->call_timeout_ms = add->call_timeout_ms!=-1 ? add->call_timeout_ms : base->call_timeout_ms;
    conf->connect_timeout_ms = add->connect_timeout_ms!=-1 ? add->connect_timeout_ms : base->connect_timeout_ms;

    return conf;
}

// Check if this connection is a ws connection
static int is_websocket_upgrade(request_rec *r)
{
    const char *upgrade = apr_table_get(r->headers_in, "Upgrade");
    const char *connection = apr_table_get(r->headers_in, "Connection");
    int upgrade_connection = 0;

    if (r->proto_num < HTTP_VERSION(1, 1)) {
        /* Upgrade requires at least HTTP/1.1. */
        return 0;
    }

    if ((upgrade != NULL) &&
        (connection != NULL) && !strcasecmp(upgrade, "WebSocket")) {
        upgrade_connection = !strcasecmp(connection, "Upgrade");
        if (!upgrade_connection) {
            char *token = ap_get_token(r->pool, &connection, 0);

            while (token && *token) {       /* Parse the Connection value */
                upgrade_connection = !strcasecmp(token, "Upgrade");
                if (upgrade_connection) {
                    break;
                }
                while (*connection == ';') {
                    ++connection;
                    ap_get_token(r->pool, &connection, 0);  /* Skip parameters */
                }
                if (*connection++ != ',') {
                    break;  /* Invalid without comma */
                }
                token =
                    (*connection) ? ap_get_token(r->pool, &connection,
                                                 0) : NULL;
            }
        }
    }

    return upgrade_connection;
}