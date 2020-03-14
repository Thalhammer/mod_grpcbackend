#pragma once
#include "pool_class.h"
extern "C" {
	#include "httpd.h"
}
#include "config.h"

class http_handler: public pool_class<http_handler> {
	request_rec* m_r;
	const grpcbackend_config_t* m_config;
public:
	http_handler(request_rec* r, grpcbackend_config_t* cfg)
		: m_r(r), m_config(cfg)
	{}
	const grpcbackend_config_t* get_config() const { return m_config; }
	int handle_request();
};