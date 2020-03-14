#include <grpc++/channel.h>
#include "handler.grpc.pb.h"
#include <sstream>
#include <string>
#include <algorithm>
#include <thread>

#include "http_handler.h"
#include "config.h"
#include "grpc_connection_provider.h"
#include "utils.h"

extern "C" {
	#include "http_log.h"
	#include "http_protocol.h"
	#include "apr_strings.h"
	APLOG_USE_MODULE(grpcbackend);
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

int http_handler::handle_request() {
	if(m_config->host == nullptr)
		return HTTP_INTERNAL_SERVER_ERROR;
	auto channel = grpc_connection_provider::get_instance().get_channel(m_config->host, m_config->connect_timeout_ms, m_r);
	if(!channel) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "grpc backend timeout");
		return HTTP_GATEWAY_TIME_OUT;
	}
	auto stub = ::thalhammer::http::Handler::NewStub(channel);

	::grpc::ClientContext context;
	if(m_config->call_timeout_ms > 0)
		context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(m_config->call_timeout_ms));

	auto stream = stub->Handle(&context);

	{
		::thalhammer::http::HandleRequest req;
		auto* client = req.mutable_client();
		auto* con = m_r->connection;
		client->set_local_port(con->local_addr->port);
		client->set_local_ip(utils::apr_addr_to_string(con->local_addr));
		client->set_remote_port(con->client_addr->port);
		client->set_remote_ip(utils::apr_addr_to_string(con->client_addr));
		client->set_encrypted(!strcmp(ap_http_scheme(m_r), "https"));
		auto* request = req.mutable_request();
		request->set_method(m_r->method);
		request->set_protocol(m_r->protocol);
		request->set_resource(m_r->unparsed_uri);
		
		auto *fields = apr_table_elts(m_r->headers_in);
		auto *e = (apr_table_entry_t *)fields->elts;
		for(int i = 0; i < fields->nelts; i++) {
			auto* header = request->add_headers();
			header->set_key(e[i].key);
			header->set_value(e[i].val);
		}

		if(!stream->Write(req)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "failed to write initial grpc request");
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "maybe backend not online ?");
			grpc_connection_provider::get_instance().reset_cache(m_config->host, m_r);
			::grpc::Status s = stream->Finish();
			if(!s.ok()) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "failed to execute rpc: %s", s.error_message().c_str());
			}
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
	}, m_r);

	if(failed || !stream->WritesDone()) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "failed to write grpc request");
		grpc_connection_provider::get_instance().reset_cache(m_config->host, m_r);
		::grpc::Status s = stream->Finish();
		if(!s.ok()) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "failed to execute rpc: %s", s.error_message().c_str());
		}
		return HTTP_BAD_GATEWAY;
	}

	::thalhammer::http::HandleResponse resp;
	if(!stream->Read(&resp)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "failed to read initial grpc response");
		grpc_connection_provider::get_instance().reset_cache(m_config->host, m_r);
		::grpc::Status s = stream->Finish();
		if(!s.ok()) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "failed to execute rpc: %s", s.error_message().c_str());
		}
		return HTTP_BAD_GATEWAY;
	} else {
		auto& response = resp.response();
		m_r->status = response.status_code();
		m_r->status_line = apr_pstrdup(m_r->pool, (std::to_string(m_r->status) + " " + response.status_message()).c_str());
		for(auto& header : response.headers()) {
			apr_table_setn(m_r->headers_out, apr_pstrdup(m_r->pool, header.key().c_str()), apr_pstrdup(m_r->pool, header.value().c_str()));
			std::string key = header.key();
			std::transform(key.begin(), key.end(), key.begin(), ::tolower);
			if(key == "content-type")
				ap_set_content_type(m_r, apr_pstrdup(m_r->pool, header.value().c_str()));
		}
		if(!response.content().empty())
		{
			auto& content = response.content();
			ap_rwrite(content.data(), content.size(), m_r);
		}
	}

	while(stream->Read(&resp)) {
		auto& content = resp.response().content();
		ap_rwrite(content.data(), content.size(), m_r);
	}

	::grpc::Status s = stream->Finish();
	if(!s.ok()) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, m_r, "failed to execute rpc: %s", s.error_message().c_str());
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return DONE;
}
