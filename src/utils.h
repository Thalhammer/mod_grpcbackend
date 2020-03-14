#pragma once
#include <string>
extern "C" {
    #include "apr_network_io.h"
    struct server_rec;
}

class utils {
public:
    static std::string apr_addr_to_string(apr_sockaddr_t* addr);
    static void print_table(struct server_rec* s, const char* name, apr_table_t* table);
};