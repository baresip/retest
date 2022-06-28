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

	ASSERT_EQ(2, av1_obu_count(buf, sizeof(buf)));

 out:
	return err;
}


static const uint64_t dummy_ts = 0x0102030405060708ULL;

struct test {
	/* input: */
	size_t pktsize;

	/* output: */
	struct mbuf *mb;
	unsigned marker_count;
	unsigned new_count;
	uint8_t w_saved;
};


static int av1_packet_handler(bool marker, uint64_t rtp_ts,
			      const uint8_t *hdr, size_t hdr_len,
			      const uint8_t *pld, size_t pld_len,
			      void *arg)
{
	struct test *test = arg;
	struct mbuf *mb = mbuf_alloc(hdr_len + pld_len);
	struct av1_aggr_hdr aggr_hdr;
	int err = 0;

	ASSERT_EQ(dummy_ts, rtp_ts);
	ASSERT_TRUE((hdr_len + pld_len) <= test->pktsize);

	err  = mbuf_write_mem(mb, hdr, hdr_len);
	err |= mbuf_write_mem(mb, pld, pld_len);
	if (err)
		goto out;

	mb->pos = 0;

	err = av1_aggr_hdr_decode(&aggr_hdr, mb);
	if (err)
		goto out;

	/* XXX: check Z and Y flags */

	test->w_saved = aggr_hdr.w;

	if (aggr_hdr.n)
		++test->new_count;

	err = mbuf_write_mem(test->mb, mbuf_buf(mb), mbuf_get_left(mb));
	if (err)
		goto out;

	if (marker) {
		++test->marker_count;
		test->mb->pos = 0;
	}

 out:
	mem_deref(mb);
	return err;
}


static int copy_obu(struct mbuf *mb_bs, const uint8_t *buf, size_t size)
{
	struct av1_obu_hdr hdr;
	struct mbuf wrap = {
		.buf = (uint8_t *)buf,
		.size = size,
		.pos = 0,
		.end = size
	};
	bool has_size = true;

	int err = av1_obu_decode(&hdr, &wrap);
	if (err) {
		DEBUG_WARNING("av1: decode: could not decode OBU"
			" [%zu bytes]: %m\n", size, err);
		return err;
	}

	switch (hdr.type) {

	case AV1_OBU_SEQUENCE_HEADER:
	case AV1_OBU_FRAME_HEADER:
	case AV1_OBU_METADATA:
	case AV1_OBU_FRAME:
	case AV1_OBU_REDUNDANT_FRAME_HEADER:
	case AV1_OBU_TILE_GROUP:

		err = av1_obu_encode(mb_bs, hdr.type, has_size,
				     hdr.size, mbuf_buf(&wrap));
		if (err)
			return err;
		break;

	case AV1_OBU_TEMPORAL_DELIMITER:
	case AV1_OBU_TILE_LIST:
	case AV1_OBU_PADDING:
		/* MUST be ignored by receivers. */
		DEBUG_WARNING("av1: decode: copy: unexpected obu type %u (%s)"
			" [x=%d, s=%d, size=%zu]\n",
			      hdr.type, av1_obu_name(hdr.type),
			hdr.x, hdr.s, hdr.size);
		return EPROTO;

	default:
		DEBUG_WARNING("av1: decode: copy: unknown obu type %u (%s)"
			" [x=%d, s=%d, size=%zu]\n",
			hdr.type, av1_obu_name(hdr.type),
			hdr.x, hdr.s, hdr.size);
		return EPROTO;
	}

	return 0;
}


static int convert_rtp_to_bs(struct mbuf *mb_bs, struct mbuf *mb_rtp,
			     uint8_t w)
{
	int err;

	/* prepend Temporal Delimiter */
	err = av1_obu_encode(mb_bs, AV1_OBU_TEMPORAL_DELIMITER, true, 0, NULL);
	if (err)
		goto out;

	if (w) {
		size_t size;

		for (unsigned i=0; i<(w - 1u); i++) {

			err = av1_leb128_decode(mb_rtp, &size);
			if (err)
				goto out;

			err = copy_obu(mb_bs, mbuf_buf(mb_rtp), size);
			if (err)
				goto out;

			mbuf_advance(mb_rtp, size);
		}

		/* last OBU element MUST NOT be preceded by a length field */
		size = mbuf_get_left(mb_rtp);

		err = copy_obu(mb_bs, mbuf_buf(mb_rtp), size);
		if (err)
			goto out;

		mbuf_advance(mb_rtp, size);
	}
	else {
		while (mbuf_get_left(mb_rtp) >= 2) {

			size_t size;

			/* each OBU element MUST be preceded by length field */
			err = av1_leb128_decode(mb_rtp, &size);
			if (err)
				goto out;

			err = copy_obu(mb_bs, mbuf_buf(mb_rtp), size);
			if (err)
				goto out;

			mbuf_advance(mb_rtp, size);
		}
	}

 out:
	return err;
}


static int test_av1_packetize_base(unsigned count_bs, unsigned count_rtp,
				   unsigned exp_w, size_t pktsize,
				   const uint8_t *buf, size_t size)
{
	struct test test;
	struct mbuf *mb_bs = mbuf_alloc(1024);
	bool new_flag = true;
	int err;

	if (!mb_bs)
		return ENOMEM;

	memset(&test, 0, sizeof(test));

	ASSERT_EQ(count_bs, av1_obu_count(buf, size));
	ASSERT_EQ(count_rtp, av1_obu_count_rtp(buf, size));

	test.pktsize = pktsize;
	test.w_saved = 255;

	test.mb = mbuf_alloc(1024);
	if (!test.mb) {
		err = ENOMEM;
		goto out;
	}

	err = av1_packetize_high(&new_flag, true, dummy_ts,
			    buf, size, test.pktsize,
			    av1_packet_handler, &test);
	if (err)
		goto out;

	ASSERT_EQ(1, test.marker_count);
	ASSERT_EQ(1, test.new_count);
	ASSERT_EQ(exp_w, test.w_saved);

	err = convert_rtp_to_bs(mb_bs, test.mb, test.w_saved);
	TEST_ERR(err);

	/* compare bitstream with test-vector */
	TEST_MEMCMP(buf, size, mb_bs->buf, mb_bs->end);

 out:
	mem_deref(test.mb);
	mem_deref(mb_bs);

	return err;
}


static const uint8_t pkt_aom[] = {

	/* Temporal Delimiter */
	0x12, 0x00,

	/* Sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,
};

static const uint8_t pkt_aom5[] = {

	/* Temporal Delimiter */
	0x12, 0x00,

	/* Sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,
};


/*
 * https://dl8.webmfiles.org/BeachDrone-AV1.webm
 *
 * frame   3:  size=320     pts=134  (0.134000 sec)
 * obu:  type=2,OBU_TEMPORAL_DELIMITER   x=0 s=1 size=0
 * obu:  type=3,OBU_FRAME_HEADER         x=0 s=1 size=23
 * obu:  type=4,OBU_TILE_GROUP           x=0 s=1 size=290
 *
 */
static const char pkt_beach[] =
	"12001a17301a2049648406a21a47fbdf"
	"cbb4180c4002041157404022a202001c"
	"64b538c87ccb8807fc1658bcd98ada85"
	"6a35745f32824a2ee8d5e11d80476188"
	"917a6662c19f0ca9eace86b8ac3ae880"
	"0561949ecbbc26f800d904d1714219a1"
	"0d1d0410370c6e0b8dead1bf1e8a291b"
	"fd0a1254a6e038998e091c7d5233b138"
	"68acf6225840618dcbfd948ed99943dd"
	"93df6037f6fda997cd2f8467b601d94e"
	"09169d57f8fa9c8d6abfcab091366231"
	"48c89c7d5a8b86544140a827f48a2b0b"
	"15d6836f4ceab733dd2f2ebbb20cb69a"
	"684dafb9403610e0560bad66b728c8fd"
	"38c315a1f63ac3d2fca0da95fdbfb9f8"
	"e61b4f18b90a455dad2fc91a32401007"
	"2942753e34c95c6d3693a555e660e6ca"
	"628a22fed94f3618d912b84a272e00da"
	"44b8cf62a7abfd5d0396e8848d8bd56d"
	"195bb21814c15700e825a4d9fe2a64f8"
	;


static int test_av1_packetize()
{
	uint8_t buf[320];
	int err;

	err = test_av1_packetize_base(2, 1, 1, 1200, pkt_aom, sizeof(pkt_aom));
	if (err)
		return err;

	err = test_av1_packetize_base(5, 4, 0, 10, pkt_aom5, sizeof(pkt_aom5));
	if (err)
		return err;

	err = str_hex(buf, sizeof(buf), pkt_beach);
	TEST_ERR(err);

	err = test_av1_packetize_base(3, 2, 2, 100, buf, sizeof(buf));
	if (err)
		return err;

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

	err = test_av1_packetize();
	if (err)
		return err;

	return err;
}
