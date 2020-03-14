#pragma once
#include "pool_class.h"
extern "C" {
	#include "httpd.h"
}
#include "config.h"

class http_handler: public pool_class<http_handler> {
	request_rec* r;
	const grpcbackend_config_t* config;
public:
	http_handler(request_rec* r);
	const grpcbackend_config_t* get_config() const { return config; }
	int handle_request();
};