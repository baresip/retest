/**
 * @file src/av1.c AV1 testcode
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <re_av1.h>
#include "test.h"


#define DEBUG_MODULE "av1test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_av1(void)
{
	static const struct test {
		uint8_t byte;
		unsigned z;
		unsigned y;
		unsigned w;
		unsigned n;
	} testv[] = {

		/* Sample aggregation headers from Chrome 102 */
		{0x28, 0, 0, 2, 1},
		{0x50, 0, 1, 1, 0},
	};
	int err = 0;

	for (size_t i=0; i<ARRAY_SIZE(testv); i++) {

		const struct test *test = &testv[i];
		struct av1_aggr_hdr hdr;
		struct mbuf mb = {
			.buf  = (uint8_t *)&test->byte,
			.size = 1,
			.pos  = 0,
			.end  = 1
		};

		err = av1_aggr_hdr_decode(&hdr, &mb);
		if (err)
			break;

		ASSERT_EQ(test->z, hdr.z);
		ASSERT_EQ(test->y, hdr.y);
		ASSERT_EQ(test->w, hdr.w);
		ASSERT_EQ(test->n, hdr.n);
	}

 out:
	return err;
}
