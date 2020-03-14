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
#include "pool_class.h"
#include <thread>
#include <atomic>


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