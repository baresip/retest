/**
 * @file auringbuf.c Audio Circular buffer Testcode
 */
#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"

#define DEBUG_MODULE "test_auringbuf"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

static int16_t sampv_in[160];
static int16_t sampv_out[160];
static int16_t sampv_zeros[160] = {0};


static void setup(void)
{
	unsigned i;
	for (i=0; i<ARRAY_SIZE(sampv_in); i++)
		sampv_in[i] = i;
	memset(sampv_out, 0, sizeof(sampv_out));
}


static int test_aligned_fill(void)
{
	int err;
	struct auringbuf *ab = NULL;

	err = auringbuf_alloc(&ab, 20, 320);
	if (err)
		goto out;

	TEST_EQUALS(0, auringbuf_cur_size(ab));

	err |= auringbuf_write_samp(ab,  sampv_in, 80);
	err |= auringbuf_write_samp(ab, &sampv_in[80], 80);
	if (err)
		goto out;

	TEST_EQUALS(320, auringbuf_cur_size(ab));

	auringbuf_read_samp(ab, sampv_out, ARRAY_SIZE(sampv_out));

	TEST_MEMCMP(sampv_in, sizeof(sampv_in), sampv_out, sizeof(sampv_out));
	TEST_EQUALS(0, auringbuf_cur_size(ab));

	/* read zeros */
	auringbuf_read_samp(ab, sampv_out, ARRAY_SIZE(sampv_out));
	TEST_MEMCMP(sampv_zeros, sizeof(sampv_zeros), sampv_out, sizeof(sampv_out));

	err = auringbuf_write_samp(ab, sampv_in, 80);
	if (err)
		goto out;
	auringbuf_read_samp(ab, sampv_out, ARRAY_SIZE(sampv_out));
	TEST_MEMCMP(sampv_zeros, sizeof(sampv_zeros), sampv_out, sizeof(sampv_out));

out:
	mem_deref(ab);

	return err;
}


static int test_unaligned_and_overrun_fill(void)
{
	int err;
	struct auringbuf *ab = NULL;

	err = auringbuf_alloc(&ab, 20, 80);
	if (err)
		goto out;

	TEST_EQUALS(0, auringbuf_cur_size(ab));

	/* test overrun: write should simply ignored */
	err |= auringbuf_write_samp(ab, sampv_in, 90);
	TEST_EQUALS(0, auringbuf_cur_size(ab));

	err |= auringbuf_write_samp(ab, sampv_in, 35);
	auringbuf_read_samp(ab, sampv_out, 35);

	TEST_EQUALS(0, auringbuf_cur_size(ab));

	err |= auringbuf_write_samp(ab, &sampv_in[35], 30);
	auringbuf_read_samp(ab, &sampv_out[35], 30);

	TEST_EQUALS(0, auringbuf_cur_size(ab));

	err |= auringbuf_write_samp(ab, &sampv_in[65], 25);
	auringbuf_read_samp(ab, &sampv_out[65], 25);

	err |= auringbuf_write_samp(ab, &sampv_in[90], 40);
	auringbuf_read_samp(ab, &sampv_out[90], 40);

	err |= auringbuf_write_samp(ab, &sampv_in[130], 30);
	auringbuf_read_samp(ab, &sampv_out[130], 30);

	if (err)
		goto out;


	TEST_MEMCMP(sampv_in, sizeof(sampv_in), sampv_out, sizeof(sampv_out));
	TEST_EQUALS(0, auringbuf_cur_size(ab));

out:
	mem_deref(ab);

	return err;

}


int test_auringbuf(void)
{
	int err;

	setup();

	err = test_aligned_fill();
	err |= test_unaligned_and_overrun_fill();

	return err;
}
