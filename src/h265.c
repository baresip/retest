/**
 * @file h265.c H.265 Testcode
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "h265test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_h265(void)
{
	uint8_t buf[H265_HDR_SIZE];
	struct h265_nal hdr;
	enum {TID = 1};
	int err;

	h265_nal_encode(buf, H265_NAL_VPS_NUT, TID);

	err = h265_nal_decode(&hdr, buf);
	if (err)
		goto out;

	ASSERT_EQ(32, hdr.nal_unit_type);
	ASSERT_EQ(TID, hdr.nuh_temporal_id_plus1);

 out:
	return err;
}
