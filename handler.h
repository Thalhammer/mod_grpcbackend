#pragma once
extern "C" {
	#include "httpd.h"
	#include "http_log.h"
	#include "http_protocol.h"
	#include "apr_strings.h"
}
#include "config.h"
extern int handle_request(request_rec* r, const grpcbackend_config_t* config);