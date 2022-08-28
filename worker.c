#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <arpa/inet.h>

#include "types.h"
#include "likely.h"
#include "vec.h"
#include "base32.h"
#include "ed25519/ed25519.h"
#include "ioutil.h"
#include "common.h"
#include "output.h"

#include "worker.h"

#include "filters.h"

#ifndef _WIN32
#define FSZ "%zu"
#else
#define FSZ "%Iu"
#endif

pthread_mutex_t keysgenerated_mutex;
volatile size_t keysgenerated = 0;
volatile int endwork = 0;

int numwords = 1;
size_t numneedgenerate = 0;

// output directory
char *workdir = 0;
size_t workdirlen = 0;

void worker_init(void)
{
	ge_initeightpoint();
}

static void yggready(const u8 *secret,const u8 *public)
{
	if (endwork)
		return;

	if (numneedgenerate) {
		pthread_mutex_lock(&keysgenerated_mutex);
		if (keysgenerated >= numneedgenerate) {
			pthread_mutex_unlock(&keysgenerated_mutex);
			return;
		}
		++keysgenerated;
		if (keysgenerated == numneedgenerate)
			endwork = 1;
		pthread_mutex_unlock(&keysgenerated_mutex);
	}

	// disabled as this was never ever triggered as far as I'm aware
#if 1
	// Sanity check that the public key matches the private one.
	ge_p3 ALIGN(16) point;
	u8 testpk[PUBLIC_LEN];
	ge_scalarmult_base(&point,secret);
	ge_p3_tobytes(testpk,&point);
	if (memcmp(testpk,public,PUBLIC_LEN) != 0) {
		fprintf(stderr,"!!! secret key mismatch !!!\n");
		abort();
	}

#endif

	unsigned long* bigpub = (unsigned long*)public;
	u8 counter = 0;
	for (long unsigned int i = 0; i < (PUBLIC_LEN / sizeof(unsigned long)); i++) {
		unsigned long v = __builtin_bswap64(bigpub[i]);
		if (v == 0) {
			counter += 8 * sizeof(unsigned long);
		} else {
			counter += __builtin_clzl(v);
			break;
		}
	}

	output_writekey(public,secret,counter);
}

#include "filters_inc.inc.h"
#include "filters_worker_i.inc.h"

#ifdef STATISTICS
#define ADDNUMSUCCESS ++st->numsuccess.v
#else
#define ADDNUMSUCCESS do ; while (0)
#endif


// in little-endian order, 32 bytes aka 256 bits
static void addsztoscalar32(u8 *dst,size_t v)
{
	int i;
	u32 c = 0;
	for (i = 0;i < 32;++i) {
		c += *dst + (v & 0xFF); *dst = c & 0xFF; c >>= 8;
		v >>= 8;
		++dst;
	}
}

#include "worker_fast.inc.h"


#if !defined(BATCHNUM)
	#define BATCHNUM 2048
#endif

size_t worker_batch_memuse(void)
{
	return (sizeof(ge_p3) + sizeof(fe) + sizeof(bytes32)) * BATCHNUM;
}

#include "worker_batch.inc.h"
