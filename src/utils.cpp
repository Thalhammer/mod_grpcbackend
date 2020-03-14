#include "utils.h"
extern "C"
{
    #include "httpd.h"
    #include "http_log.h"
    APLOG_USE_MODULE(grpcbackend);
}

std::string utils::apr_addr_to_string(apr_sockaddr_t *addr)
{
    std::string res(addr->addr_str_len, 0x00);
    apr_sockaddr_ip_getbuf((char *)res.data(), res.size(), addr);
    res.resize(strlen(res.c_str()));
    return res;
}

void utils::print_table(request_rec *r, const char *name, apr_table_t *table)
{
    auto *fields = apr_table_elts(table);
    auto *e = (apr_table_entry_t *)fields->elts;
    if (fields->nelts == 0)
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s table empty", name);
    for (int i = 0; i < fields->nelts; i++)
    {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s: %s = %s", name, e[i].key, e[i].val);
    }
}