#include "handler.h"
#include "config.h"
#include "http_config.h"
#include "ap_config.h"
#include <iostream>

static int grpcbackend_handler(request_rec *r);
static void grpcbackend_register_hooks(apr_pool_t *p);
static const char* grpcbackend_set_enabled(cmd_parms* cmd, void* cfg, const char* arg);
static const char* grpcbackend_set_host(cmd_parms* cmd, void* cfg, const char* arg);
static const char* grpcbackend_set_calltimeout(cmd_parms* cmd, void* cfg, const char* arg);
static const char* grpcbackend_set_connecttimeout(cmd_parms* cmd, void* cfg, const char* arg);
static void* grpcbackend_create_dir_conf(apr_pool_t* pool, char* context);
static void* grpcbackend_merge_dir_conf(apr_pool_t* pool, void* BASE, void* ADD);

static const command_rec grpcbackend_directives[] = {
    AP_INIT_TAKE1("grpcEnabled", (cmd_func)grpcbackend_set_enabled, NULL, ACCESS_CONF, "Enabled or disable mod_grpcbackend"),
    AP_INIT_TAKE1("grpcHost", (cmd_func)grpcbackend_set_host, NULL, ACCESS_CONF, "Set GRPC Service host (and port)"),
    AP_INIT_TAKE1("grpcCallTimeout", (cmd_func)grpcbackend_set_calltimeout, NULL, ACCESS_CONF, "Set call timeout"),
    AP_INIT_TAKE1("grpcConnectTimeout", (cmd_func)grpcbackend_set_connecttimeout, NULL, ACCESS_CONF, "Set connect timeout"),
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
    auto* config = static_cast<grpcbackend_config_t*>(ap_get_module_config(r->per_dir_config, &grpcbackend_module));
    if (!config->enabled || strcmp(r->handler, "grpcbackend")) {
        return DECLINED;
    }
    if(!strcmp(r->uri, "/config")) {
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "GRPC enabled: %s\n", (config->enabled)?"true":"false");
        ap_rprintf(r, "GRPC call timeout: %s\n", std::to_string(config->call_timeout_ms).c_str());
        ap_rprintf(r, "GRPC connect timeout: %s\n", std::to_string(config->connect_timeout_ms).c_str());
        ap_rprintf(r, "GRPC host:    %s\n", config->host);
        return DONE;
    }
    return handle_request(r, config);
}

static void grpcbackend_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(grpcbackend_handler, NULL, NULL, APR_HOOK_LAST);
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

static void* grpcbackend_merge_dir_conf(apr_pool_t* pool, void* BASE, void* ADD) {
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