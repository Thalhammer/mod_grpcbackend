#pragma once
#include <memory>
#include <mutex>
#include <map> 

namespace grpc_impl {
    class Channel;
}
namespace grpc { typedef ::grpc_impl::Channel Channel;}

class grpc_connection_provider {
	struct con_entry;
	std::mutex mtx;
	std::map<std::string, con_entry> channels;
public:
	grpc_connection_provider();
	~grpc_connection_provider();
	std::shared_ptr<::grpc::Channel> get_channel(const char* host, int64_t timeout);
	void reset_cache(const char* host);

    static grpc_connection_provider& get_instance();
};