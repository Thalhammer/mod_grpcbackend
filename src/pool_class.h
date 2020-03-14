#pragma once
extern "C" {
	#include "apr_errno.h"
	#include "apr_pools.h"
}

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