#pragma once
#include "handler.grpc.pb.h"
extern "C" {
	#include "httpd.h"
	#include "http_log.h"
	#include "http_protocol.h"
	#include "apr_strings.h"
}
#include "config.h"
#include "websocket_plugin.h"
#include <thread>
#include <atomic>
template<typename T>
class pool_class {
	static apr_status_t cleanup(void* ptr) {
		if(ptr != nullptr) {
			T* instance = (T*)ptr;
			instance->~T();
		}
		return APR_SUCCESS;
	}
	apr_pool_t* _pool;
public:
	template<typename... Args>
	static T* create(apr_pool_t* pool, Args&&... args) {
		auto* mem = apr_palloc(pool, sizeof(T));
		new(mem) T(std::forward<Args>(args)...);
		apr_pool_cleanup_register(pool, mem, cleanup, apr_pool_cleanup_null) ;
		return (T*)mem;
	}

	virtual ~pool_class() {
	}
};

class http_handler: public pool_class<http_handler> {
	request_rec* r;
	const grpcbackend_config_t* config;
public:
	http_handler(request_rec* r);
	const grpcbackend_config_t* get_config() const { return config; }
	int handle_request();
};

class websocket_handler: public pool_class<websocket_handler> {
	std::thread _recv_thread;
	std::atomic<bool> _recv_shutdown;
	const WebSocketServer* _server;
	std::unique_ptr<::thalhammer::http::Handler::Stub> _stub;
	::grpc::ClientContext _call_context;
	std::unique_ptr<::grpc::ClientReaderWriterInterface<::thalhammer::http::HandleWebSocketRequest, ::thalhammer::http::HandleWebSocketResponse>> _stream;
protected:
	void send(int type, const uint8_t* buffer, size_t buffer_size);
public:
	websocket_handler(const WebSocketServer* server);
	virtual ~websocket_handler();
	void on_message(int type, const uint8_t* buffer, size_t buffer_size);
	void on_disconnect();
};