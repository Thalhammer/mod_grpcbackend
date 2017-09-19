#pragma once
#include <cstdint>
typedef struct {
	struct ConfigBool {
		bool value;
		bool initialized = false;

		ConfigBool& operator=(bool b) {
			this->value = b;
			this->initialized = true;
			return *this;
		}

		operator bool() const {
			return initialized && value;
		}
	};

	ConfigBool enabled;
	const char* host;
	int64_t call_timeout_ms;
	int64_t connect_timeout_ms;
} grpcbackend_config_t;
