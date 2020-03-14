#include <grpc++/channel.h>
#include <sstream>
#include <string>
#include <algorithm>
#include <thread>

#include "websocket_handler.h"
#include "config.h"
#include "grpc_connection_provider.h"
#include "utils.h"

extern "C" {
	APLOG_USE_MODULE(grpcbackend);
}

void websocket_handler::send(int type, const uint8_t* buffer, size_t buffer_size)
{
	m_server->send(m_server, type, buffer, buffer_size);
}

websocket_handler::websocket_handler(const WebSocketServer* server)
	: m_recv_shutdown(false), m_server(server)
{}

bool websocket_handler::init()
{
	auto* r = m_server->request(m_server);
	auto* config = static_cast<grpcbackend_config_t*>(ap_get_module_config(r->per_dir_config, &grpcbackend_module));
	if(!config->host){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "missing grpc host");
		return false;
	}
	auto channel = grpc_connection_provider::get_instance().get_channel(config->host, config->connect_timeout_ms, r);

	if(!channel) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "grpc backend timeout");
		return false;
	}

	m_stub = ::thalhammer::http::Handler::NewStub(channel);
	m_stream = m_stub->HandleWebSocket(&m_call_context);

	{
		::thalhammer::http::HandleWebSocketRequest req;
		auto* client = req.mutable_request()->mutable_client();
		auto* con = r->connection;
		client->set_local_port(con->local_addr->port);
		client->set_local_ip(utils::apr_addr_to_string(con->local_addr));
		client->set_remote_port(con->client_addr->port);
		client->set_remote_ip(utils::apr_addr_to_string(con->client_addr));
		client->set_encrypted(!strcmp(ap_http_scheme(r), "https"));
		auto* request = req.mutable_request();
		request->set_method(r->method);
		request->set_protocol(r->protocol);
		request->set_resource(r->unparsed_uri);
		
		auto *fields = apr_table_elts(r->headers_in);
		auto *e = (apr_table_entry_t *)fields->elts;
		for(int i = 0; i < fields->nelts; i++) {
			auto* header = request->add_headers();
			header->set_key(e[i].key);
			header->set_value(e[i].val);
		}

		if(!m_stream->Write(req)) {
			grpc_connection_provider::get_instance().reset_cache(config->host, r);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "failed to write initial grpc request");
			return false;
		}
	}

	::thalhammer::http::HandleWebSocketResponse resp;
	if(!m_stream->Read(&resp)) {
		grpc_connection_provider::get_instance().reset_cache(config->host, r);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "failed to read initial grpc response");
		return false;
	} else {
		for(auto& header : resp.response().headers()) {
			apr_table_setn(r->headers_out, apr_pstrdup(r->pool, header.key().c_str()), apr_pstrdup(r->pool, header.value().c_str()));
			std::string key = header.key();
			std::transform(key.begin(), key.end(), key.begin(), ::tolower);
		}
	}

	m_recv_thread = std::thread([this,r, initial_response = resp](){
		try {
			::thalhammer::http::HandleWebSocketResponse resp = initial_response;
			do {
				if(!resp.has_message()) continue;
				auto& msg = resp.message();
				int mtype = MESSAGE_TYPE_INVALID;
				switch(msg.type()) {
					case ::thalhammer::http::WebSocketMessage::TEXT:
						mtype = MESSAGE_TYPE_TEXT; break;
					case ::thalhammer::http::WebSocketMessage::BINARY:
						mtype = MESSAGE_TYPE_BINARY; break;
					case ::thalhammer::http::WebSocketMessage::CLOSE:
						m_server->close(m_server);
						m_recv_shutdown = true;
						break;
					default:
						break;
				}
				if(mtype != MESSAGE_TYPE_INVALID) {
					auto& content = msg.content();
					this->send(mtype, (const uint8_t*)content.data(), content.size());
				}
			} while(!m_recv_shutdown && m_stream->Read(&resp));
		} catch(...) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "exception in read thread");
		}
	});
	return true;
}

websocket_handler::~websocket_handler()
{
}

void websocket_handler::on_message(int type, const uint8_t* buffer, size_t buffer_size)
{
	::thalhammer::http::HandleWebSocketRequest req;
	auto* msg = req.mutable_message();
	switch(type) {
		case MESSAGE_TYPE_TEXT:
			msg->set_type(::thalhammer::http::WebSocketMessage::TEXT); break;
		case MESSAGE_TYPE_BINARY:
			msg->set_type(::thalhammer::http::WebSocketMessage::BINARY); break;
	}
	msg->set_content((const char*)buffer, buffer_size);

	if(!m_stream->Write(req))
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_server->request(m_server), "failed to send websocket message to backend");
	}
}

void websocket_handler::on_disconnect()
{
	::thalhammer::http::HandleWebSocketRequest req;
	auto* msg = req.mutable_message();
	msg->set_type(::thalhammer::http::WebSocketMessage::CLOSE);
	msg->set_content("");
	m_stream->WriteLast(req, ::grpc::WriteOptions());

	m_recv_shutdown = true;
	::grpc::Status s = m_stream->Finish();
	if(!s.ok()) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_server->request(m_server), "failed to execute rpc: %s", s.error_message().c_str());
	}
	if(m_recv_thread.joinable())
		m_recv_thread.join();
}

