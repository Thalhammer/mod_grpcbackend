#include "grpc_connection_provider.h"
#include <grpc++/channel.h>
#include <grpc++/create_channel.h>

struct grpc_connection_provider::con_entry
{
	std::shared_ptr<::grpc::Channel> channel;
	unsigned int num_reqs;
};

grpc_connection_provider::grpc_connection_provider()
{
}

grpc_connection_provider::~grpc_connection_provider()
{
}

std::shared_ptr<::grpc::Channel> grpc_connection_provider::get_channel(const char *host, int64_t timeout)
{
	std::unique_lock<std::mutex> lck(mtx);
	std::shared_ptr<::grpc::Channel> channel;
	if (channels.count(host))
	{
		auto entry = channels.at(host);
		channel = entry.channel;
		auto state = channel->GetState(true);
		if (entry.num_reqs++ > 20 || state == grpc_connectivity_state::GRPC_CHANNEL_TRANSIENT_FAILURE || state == grpc_connectivity_state::GRPC_CHANNEL_TRANSIENT_FAILURE)
		{
			channel.reset();
			channels.erase(host);
		}
	}

	if (!channel)
	{
		printf("ConProvider create channel to %s\n", host);
		channel = grpc::CreateChannel(host, grpc::InsecureChannelCredentials());
		con_entry entry{channel, 0};
		channels.insert({host, entry});
	}

	if (timeout > 0)
	{
		if (!channel->WaitForConnected(std::chrono::system_clock::now() + std::chrono::milliseconds(timeout)))
		{
			return nullptr;
		}
	}

	return channel;
}

void grpc_connection_provider::reset_cache(const char *host)
{
	std::unique_lock<std::mutex> lck(mtx);
	channels.erase(host);
}

static grpc_connection_provider instance;

grpc_connection_provider &grpc_connection_provider::get_instance()
{
	return instance;
}