#include <grpc++/grpc++.h>
#include "handler.grpc.pb.h"
#include <sstream>
#include <string>
#include <algorithm>
#include <thread>

#include "handler.h"
#include "config.h"

extern "C" {
	APLOG_USE_MODULE(grpcbackend);
}
#define LOGSTR(x) ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "%s", x)

std::string apr_addr_to_string(apr_sockaddr_t* addr)
{
	std::string res(addr->addr_str_len, 0x00);
	apr_sockaddr_ip_getbuf((char*)res.data(), res.size(), addr);
	res.resize(strlen(res.c_str()));
	return res;
}

template<typename Func>
size_t read_body(Func func, request_rec* r) {

	size_t total_size = 0;
	bool seen_eos = false;
	auto *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    do {
        apr_bucket *bucket = NULL, *last = NULL;

        int rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            apr_brigade_destroy(bb);
            break;
        }

        for (bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb);
             last = bucket, bucket = APR_BUCKET_NEXT(bucket)) {
            const char *data;
            apr_size_t len;

            if (last) {
                apr_bucket_delete(last);
            }
            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = true;
                break;
            }
            if (bucket->length == 0) {
                continue;
            }

            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
				apr_brigade_destroy(bb);
				seen_eos = true;
				break;
			}
			
			if(!func(data, len))
				break;
			total_size += len;
        }

        apr_brigade_cleanup(bb);
	} while (!seen_eos);
	
	return total_size;
}

void print_table(server_rec* s, const char* name, apr_table_t* table) {
	auto *fields = apr_table_elts(table);
	auto *e = (apr_table_entry_t *)fields->elts;
	if(fields->nelts == 0)
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s table empty", name);
	for(int i = 0; i < fields->nelts; i++) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s: %s = %s",name, e[i].key, e[i].val);
	}
}

class grpc_connection_provider {
	struct con_entry {
		std::shared_ptr<::grpc::Channel> channel;
		unsigned int num_reqs;
	};

	std::mutex mtx;
	std::map<std::string, con_entry> channels;
public:
	grpc_connection_provider() {
	}
	~grpc_connection_provider() {
	}

	std::unique_ptr<::thalhammer::http::Handler::Stub> getStub(const char* host, int64_t timeout) {
		std::unique_lock<std::mutex> lck(mtx);
		std::shared_ptr<::grpc::Channel> channel;
		if(channels.count(host)) {
			auto entry = channels.at(host);
			channel = entry.channel;
			auto state = channel->GetState(true);
			if(entry.num_reqs++ > 20 || state == grpc_connectivity_state::GRPC_CHANNEL_TRANSIENT_FAILURE || state == grpc_connectivity_state::GRPC_CHANNEL_TRANSIENT_FAILURE) {
				channel.reset();
				channels.erase(host);
			}
		}
		
		if(!channel) {
			printf("ConProvider create channel to %s\n", host);
			channel = grpc::CreateChannel(host, grpc::InsecureChannelCredentials());
			con_entry entry { channel, 0 };
			channels.insert({ host, entry });
		}

		if(timeout > 0) {
			if(!channel->WaitForConnected(std::chrono::system_clock::now() + std::chrono::milliseconds(timeout))) {
				return nullptr;
			}
		}

		return ::thalhammer::http::Handler::NewStub(channel);
	}

	void reset_cache(const char* host) {
		std::unique_lock<std::mutex> lck(mtx);
		channels.erase(host);
	}
};

static grpc_connection_provider con_provider;

http_handler::http_handler(request_rec* r) {
	this->r = r;
	this->config = static_cast<grpcbackend_config_t*>(ap_get_module_config(r->per_dir_config, &grpcbackend_module));
}

int http_handler::handle_request() {
	if(config->host == nullptr)
		return HTTP_INTERNAL_SERVER_ERROR;
	auto stub = con_provider.getStub(config->host, config->connect_timeout_ms);	
	
	if(!stub) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GRPC Backend timeout");
		return HTTP_GATEWAY_TIME_OUT;
	}

	::grpc::ClientContext context;
	if(config->call_timeout_ms > 0)
		context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(config->call_timeout_ms));

	auto stream = stub->Handle(&context);

	{
		::thalhammer::http::HandleRequest req;
		auto* client = req.mutable_client();
		auto* con = r->connection;
		client->set_local_port(con->local_addr->port);
		client->set_local_ip(apr_addr_to_string(con->local_addr));
		client->set_remote_port(con->client_addr->port);
		client->set_remote_ip(apr_addr_to_string(con->client_addr));
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

		if(!stream->Write(req)) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Failed to write initial grpc request");
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Maybe backend not online ?");
			con_provider.reset_cache(config->host);
			return HTTP_SERVICE_UNAVAILABLE;
		}
	}

	bool failed = false;
	read_body([&stream, &failed](const char* data, size_t len){
		::thalhammer::http::HandleRequest req;
		req.mutable_request()->set_content(data, len);
		if(!stream->Write(req))
			failed = true;
		return !failed;
	}, r);

	if(failed || !stream->WritesDone()) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Failed to write grpc request");
		con_provider.reset_cache(config->host);
		return HTTP_BAD_GATEWAY;
	}

	::thalhammer::http::HandleResponse resp;
	if(!stream->Read(&resp)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Failed to read initial grpc response");
		con_provider.reset_cache(config->host);
		return HTTP_BAD_GATEWAY;
	} else {
		auto& response = resp.response();
		r->status = response.status_code();
		r->status_line = apr_pstrdup(r->pool, (std::to_string(r->status) + " " + response.status_message()).c_str());
		for(auto& header : response.headers()) {
			apr_table_setn(r->headers_out, apr_pstrdup(r->pool, header.key().c_str()), apr_pstrdup(r->pool, header.value().c_str()));
			std::string key = header.key();
			std::transform(key.begin(), key.end(), key.begin(), ::tolower);
			if(key == "content-type")
				ap_set_content_type(r, apr_pstrdup(r->pool, header.value().c_str()));
		}
		if(!response.content().empty())
		{
			auto& content = response.content();
			ap_rwrite(content.data(), content.size(), r);
		}
	}

	while(stream->Read(&resp)) {
		auto& content = resp.response().content();
		ap_rwrite(content.data(), content.size(), r);
	}

	::grpc::Status s = stream->Finish();
	if(!s.ok()) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Failed to execute rpc: %s", s.error_message().c_str());
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return DONE;
}

void websocket_handler::send(int type, const uint8_t* buffer, size_t buffer_size)
{
	_server->send(_server, type, buffer, buffer_size);
}

websocket_handler::websocket_handler(const WebSocketServer* server)
	: _server(server)
{
	auto* r = server->request(server);
	auto* config = static_cast<grpcbackend_config_t*>(ap_get_module_config(r->per_dir_config, &grpcbackend_module));
	if(!config->host)
		throw std::runtime_error("Missing grpc host");
	_stub = con_provider.getStub(config->host, config->connect_timeout_ms);

	if(!_stub) {
		throw std::runtime_error("GRPC Backend timeout");
	}

	_stream = _stub->HandleWebSocket(&_call_context);

	{
		::thalhammer::http::HandleWebSocketRequest req;
		auto* client = req.mutable_request()->mutable_client();
		auto* con = r->connection;
		client->set_local_port(con->local_addr->port);
		client->set_local_ip(apr_addr_to_string(con->local_addr));
		client->set_remote_port(con->client_addr->port);
		client->set_remote_ip(apr_addr_to_string(con->client_addr));
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

		if(!_stream->Write(req)) {
			con_provider.reset_cache(config->host);
			throw std::runtime_error("Failed to write initial grpc request");
		}
	}

	{
		::thalhammer::http::HandleWebSocketResponse resp;
		if(!_stream->Read(&resp)) {
			con_provider.reset_cache(config->host);
			throw std::runtime_error("Failed to read initial grpc response");
		} else {
			for(auto& header : resp.response().headers()) {
				apr_table_setn(r->headers_out, apr_pstrdup(r->pool, header.key().c_str()), apr_pstrdup(r->pool, header.value().c_str()));
				std::string key = header.key();
				std::transform(key.begin(), key.end(), key.begin(), ::tolower);
			}
		}
	}

	_recv_thread = std::thread([this,r](){
		try {
			::thalhammer::http::HandleWebSocketResponse resp;
			while(!_recv_shutdown && _stream->Read(&resp)) {
				auto& msg = resp.message();
				int mtype = MESSAGE_TYPE_INVALID;
				switch(msg.type()) {
					case ::thalhammer::http::WebSocketMessage::TEXT:
						mtype = MESSAGE_TYPE_TEXT; break;
					case ::thalhammer::http::WebSocketMessage::BINARY:
						mtype = MESSAGE_TYPE_BINARY; break;
					case ::thalhammer::http::WebSocketMessage::CLOSE:
						_server->close(_server);
						_recv_shutdown = true;
						break;
					default:
						break;
				}
				if(mtype != MESSAGE_TYPE_INVALID) {
					auto& content = msg.content();
					this->send(mtype, (const uint8_t*)content.data(), content.size());
				}
			}
		} catch(...) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Exception in read thread");
		}
	});
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

	if(!_stream->Write(req))
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, _server->request(_server)->server, "Failed to send websocket message to backend");
	}
}

void websocket_handler::on_disconnect()
{
	::thalhammer::http::HandleWebSocketRequest req;
	auto* msg = req.mutable_message();
	msg->set_type(::thalhammer::http::WebSocketMessage::CLOSE);
	msg->set_content("");
	_stream->WriteLast(req, ::grpc::WriteOptions());

	_recv_shutdown = true;
	::grpc::Status s = _stream->Finish();
	if(!s.ok()) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, _server->request(_server)->server, "Failed to execute rpc: %s", s.error_message().c_str());
	}
	if(_recv_thread.joinable())
		_recv_thread.join();
}

