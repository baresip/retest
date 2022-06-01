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


static int test_av1_aggr(void)
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


static int test_av1_obu(void)
{
	struct av1_obu_hdr hdr;
	static const uint8_t buf[] = {

		/* libaom OBU_TEMPORAL_DELIMITER [type=2 x=0 s=1 size=0] */
		0x12, 0x00,

		/* libaom OBU_SEQUENCE_HEADER [type=1 x=0 s=1 size=12] */
		0x0a, 0x0c, 0x00, 0x00,
		0x00, 0x04, 0x3c, 0xff,
		0xbf, 0x81, 0xb5, 0x32,
		0x00, 0x80
	};
	struct mbuf mb = {
		.buf  = (uint8_t *)buf,
		.size = sizeof(buf),
		.pos  = 0,
		.end  = sizeof(buf)
	};
	int err;

	err = av1_obu_decode(&hdr, &mb);
	if (err)
		goto out;

	ASSERT_EQ(2, hdr.type);
	ASSERT_EQ(0, hdr.x);
	ASSERT_EQ(1, hdr.s);
	ASSERT_EQ(0, hdr.size);

	err = av1_obu_decode(&hdr, &mb);
	if (err)
		goto out;

	ASSERT_EQ(1, hdr.type);
	ASSERT_EQ(0, hdr.x);
	ASSERT_EQ(1, hdr.s);
	ASSERT_EQ(12, hdr.size);

 out:
	return err;
}


int test_av1(void)
{
	int err;

	err = test_av1_aggr();
	if (err)
		return err;

	err = test_av1_obu();
	if (err)
		return err;

	return err;
}
