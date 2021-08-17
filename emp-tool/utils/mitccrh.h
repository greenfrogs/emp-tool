#ifndef EMP_MITCCRH_H__
#define EMP_MITCCRH_H__
#include "emp-tool/utils/aes_opt.h"
#include <stdio.h>
#include <condition_variable>
#include "emp-tool/utils/readerwritercircularbuffer.h"

#define QUEUE_SIZE 128
#define BATCH_SIZE 8

#define USE_THREAD 1

namespace emp {

#if USE_THREAD == 1
std::atomic_bool ks_worker_thread = ATOMIC_VAR_INIT(true);
void ks_worker(uint64_t starting_gid, block start_point, moodycamel::BlockingReaderWriterCircularBuffer<AES_KEY> *queue) {
	uint64_t gid = starting_gid;

	while(ks_worker_thread) {
		block keys[BATCH_SIZE];
		AES_KEY local_scheduled_key[BATCH_SIZE];
		for(int i = 0; i < BATCH_SIZE; ++i)
			keys[i] = start_point ^ makeBlock(gid++, 0);
		AES_opt_key_schedule<BATCH_SIZE>(keys, local_scheduled_key);
		for (int i = 0; i < BATCH_SIZE; ++i) {
			queue->wait_enqueue(local_scheduled_key[i]);
		}
	}
}
#endif

/*
 * [REF] Implementation of "Better Concrete Security for Half-Gates Garbling (in the Multi-Instance Setting)"
 * https://eprint.iacr.org/2019/1168.pdf
 */

template<int BatchSize = BATCH_SIZE>
class MITCCRH { public:
	AES_KEY scheduled_key[BATCH_SIZE];
	int key_used = BatchSize;
	block start_point;
	std::thread *worker;
	int gid = 0;

	#if USE_THREAD == 1
		moodycamel::BlockingReaderWriterCircularBuffer<AES_KEY> *queue;
	#else
		block keys[BatchSize];
	#endif
	

	MITCCRH() {
		std::cout << "MITCCRH: constructor" << std::endl;
	}

	#if USE_THREAD == 1	
	~MITCCRH() {
		ks_worker_thread = false;
	}
	#endif

	void setS(block sin) {
		std::cout << "MITCCRH: set_s" << std::endl;
		this->start_point = sin;
		#if USE_THREAD == 1	
		start_thread();
		#endif
	}

	void renew_ks(uint64_t gid) {
		std::cout << "MITCCRH: renew_ks" << std::endl;
		this->gid = gid;
		#if USE_THREAD == 1	
			start_thread();
		#else
			renew_ks();
		#endif
	}

	#if USE_THREAD == 1	
	void start_thread() {
		if (worker != nullptr) {
			std::cout << "MITCCRH: thread abandonded" << std::endl;
		}
		std::cout << "MITCCRH: start thread" << std::endl;
		this->queue = new moodycamel::BlockingReaderWriterCircularBuffer<AES_KEY>(128);
		worker = new std::thread(ks_worker, this->gid, std::ref(start_point), this->queue);
	}
	#endif

	void renew_ks() {
		#if USE_THREAD == 1	
		for (int i = 0; i < BatchSize; ++i) {
			gid++;
			queue->wait_dequeue(scheduled_key[i]);
		}
		#else
		for(int i = 0; i < BatchSize; ++i)
			keys[i] = start_point ^ makeBlock(gid++, 0);
		AES_opt_key_schedule<BatchSize>(keys, scheduled_key);
		#endif
		key_used = 0;
	}

	template<int K, int H>
	void hash_cir(block * blks) {
		for(int i = 0; i < K*H; ++i)
			blks[i] = sigma(blks[i]);
		hash<K, H>(blks);
	}

	template<int K, int H>
	void hash(block * blks) {
		assert(K <= BatchSize);
		assert(BatchSize % K == 0);
		if(key_used == BatchSize) renew_ks();

		block tmp[K*H];
		for(int i = 0; i < K*H; ++i)
			tmp[i] = blks[i];
		
		ParaEnc<K,H>(tmp, scheduled_key+key_used);
		key_used += K;
		
		for(int i = 0; i < K*H; ++i)
			blks[i] = blks[i] ^ tmp[i];
	}

};
}
#endif// MITCCRH_H__