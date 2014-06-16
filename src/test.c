/**
 * @file test.c  Regression testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


typedef int (test_exec_h)(void);

struct test {
	test_exec_h *exec;
	const char *name;
};

#define TEST(a) {a, #a}

static const struct test tests[] = {
	TEST(test_aes),
	TEST(test_aubuf),
	TEST(test_base64),
	TEST(test_bfcp),
	TEST(test_bfcp_bin),
	TEST(test_conf),
	TEST(test_crc32),
	TEST(test_dns_hdr),
	TEST(test_dns_rr),
	TEST(test_dns_dname),
	TEST(test_dsp),
#ifdef USE_TLS
	TEST(test_dtls),
#endif
	TEST(test_fir),
	TEST(test_fmt_human_time),
	TEST(test_fmt_param),
	TEST(test_fmt_pl),
	TEST(test_fmt_pl_u32),
	TEST(test_fmt_pl_u64),
	TEST(test_fmt_pl_x3264),
	TEST(test_fmt_print),
	TEST(test_fmt_regex),
	TEST(test_fmt_snprintf),
	TEST(test_fmt_str),
	TEST(test_g711_alaw),
	TEST(test_g711_ulaw),
	TEST(test_hash),
	TEST(test_hmac_sha1),
	TEST(test_http),
	TEST(test_http_loop),
	TEST(test_httpauth_chall),
	TEST(test_httpauth_resp),
	TEST(test_ice),
	TEST(test_jbuf),
	TEST(test_list),
	TEST(test_list_ref),
	TEST(test_mbuf),
	TEST(test_md5),
	TEST(test_mem),
	TEST(test_mqueue),
	TEST(test_remain),
	TEST(test_rtp),
	TEST(test_rtcp_encode),
	TEST(test_rtcp_encode_afb),
	TEST(test_rtcp_decode),
	TEST(test_sa_class),
	TEST(test_sa_cmp),
	TEST(test_sa_decode),
	TEST(test_sa_ntop),
	TEST(test_sdp_all),
	TEST(test_sdp_bfcp),
	TEST(test_sdp_parse),
	TEST(test_sdp_oa),
	TEST(test_sha1),
	TEST(test_sip_addr),
	TEST(test_sip_apply),
	TEST(test_sip_hdr),
	TEST(test_sip_param),
	TEST(test_sip_parse),
	TEST(test_sip_via),
	TEST(test_sipsess),
	TEST(test_srtp),
	TEST(test_stun_req),
	TEST(test_stun_resp),
	TEST(test_stun_reqltc),
	TEST(test_sys_div),
	TEST(test_sys_endian),
	TEST(test_sys_rand),
	TEST(test_tcp),
	TEST(test_telev),
#ifdef USE_TLS
	TEST(test_tls),
#endif
	TEST(test_tmr),
	TEST(test_turn),
	TEST(test_udp),
	TEST(test_uri),
	TEST(test_uri_cmp),
	TEST(test_uri_encode),
	TEST(test_uri_headers),
	TEST(test_uri_user),
	TEST(test_uri_params_headers),
	TEST(test_vid),
	TEST(test_vidconv),
	TEST(test_websock),
};


typedef int (ftest_exec_h)(struct mbuf *mb);

struct ftest {
	ftest_exec_h *exec;
	const char *name;
};

#define FTEST(a) {a, #a}

static const struct ftest fuztests[] = {
	FTEST(fuzzy_bfcp),
	FTEST(fuzzy_rtp),
	FTEST(fuzzy_rtcp),
	FTEST(fuzzy_sipmsg),
	FTEST(fuzzy_stunmsg),
	FTEST(fuzzy_sdpsess),
};


static const struct test *find_test(const char *name)
{
	size_t i;

	for (i=0; i<ARRAY_SIZE(tests); i++) {

		if (0 == str_casecmp(name, tests[i].name))
			return &tests[i];
	}

	return NULL;
}


static const struct ftest *find_ftest(const char *name)
{
	size_t i;

	for (i=0; i<ARRAY_SIZE(fuztests); i++) {

		if (0 == str_casecmp(name, fuztests[i].name))
			return &fuztests[i];
	}

	return NULL;
}


static int testcase_oom(const struct test *test, int levels, int *max_alloc)
{
	int j;
	int err = 0;
	bool oom = false;

	(void)re_fprintf(stderr, "  %-24s: ", test->name);

	/* All memory levels */
	for (j=levels; j>=0; j--) {
		mem_threshold_set(j);

		err = test->exec();
		if (!err)
			continue;

		if (ENOMEM == err) {
			*max_alloc = max(j, *max_alloc);
			if (!oom) {
				(void)re_fprintf(stderr, "oom max %d\n", j);
				if (j >= (int)levels) {
					DEBUG_WARNING("levels=%u\n",
						      levels);
				}
			}
			oom = true;
			continue;
		}

		DEBUG_WARNING("%s: oom threshold=%u: %m\n",
			      test->name, j, err);
		break;
	}

	if (err && ENOMEM != err) {
		DEBUG_WARNING("%s: oom test failed (%m)\n", test->name,
			      err);
		return err;
	}
	else if (0 == err) {
		(void)re_fprintf(stderr, "no allocs\n");
	}

	return 0;
}


int test_oom(const char *name)
{
	size_t i;
	int max_alloc = 0;
	const int levels = 100;
	int err = 0;

	(void)re_fprintf(stderr, "oom tests %u levels: \n", levels);

	if (name) {
		const struct test *test = find_test(name);
		if (!test) {
			(void)re_fprintf(stderr, "no such test: %s\n", name);
			return ENOENT;
		}

		err = testcase_oom(test, levels, &max_alloc);
	}
	else {
		/* All test cases */
		for (i=0; i<ARRAY_SIZE(tests) && !err; i++) {
			err = testcase_oom(&tests[i], levels, &max_alloc);
		}
	}

	mem_threshold_set(-1);

	if (err) {
		DEBUG_WARNING("oom: %m\n", err);
	}
	else {
		(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\t"
				 "(max alloc %d)\n", max_alloc);
	}

	return err;
}


static int test_unit(const char *name)
{
	size_t i;
	int err = 0;

	if (name) {
		const struct test *test = find_test(name);
		if (!test) {
			(void)re_fprintf(stderr, "no such test: %s\n", name);
			return ENOENT;
		}

		err = test->exec();
		if (err) {
			DEBUG_WARNING("%s: test failed (%m)\n", name, err);
			return err;
		}
	}
	else {
		for (i=0; i<ARRAY_SIZE(tests); i++) {
			err = tests[i].exec();
			if (err) {
				DEBUG_WARNING("%s: test failed (%m)\n",
					      tests[i].name, err);
				return err;
			}
		}
	}

	return err;
}


int test_perf(const char *name, uint32_t n)
{
	uint64_t tick, tock;
	uint32_t i;

	(void)re_fprintf(stderr, "performance tests:   ");

	tick = tmr_jiffies();

	for (i=0; i<n; i++) {
		int err;

		err = test_unit(name);
		if (err)
			return err;
	}

	tock = tmr_jiffies();

	(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m");

	(void)re_fprintf(stderr, "\t(%u tests took %lu ms)\n",
			 n, (uint32_t)(tock - tick));

	return 0;
}


int test_reg(const char *name)
{
	int err;

	(void)re_fprintf(stderr, "regular tests:       ");
	err = test_unit(name);
	if (err)
		return err;
	(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\n");

	return err;
}


#ifdef HAVE_PTHREAD
struct thread {
	const struct test *test;
	pthread_t tid;
	int err;
};


static void *thread_handler(void *arg)
{
	struct thread *thr = arg;
	int err;

	err = re_thread_init();
	if (err) {
		DEBUG_WARNING("thread: re_thread_init failed %m\n", err);
		thr->err = err;
		return NULL;
	}

	err = thr->test->exec();
	if (err) {
		DEBUG_WARNING("%s: test failed (%m)\n", thr->test->name, err);
	}

	re_thread_close();

	/* safe to write it, main thread is waiting for us */
	thr->err = err;

	return NULL;
}


/* Run all test-cases in multiple threads */
int test_multithread(void)
{
#define NUM_REPEAT 2
#define NUM_TOTAL  (NUM_REPEAT * ARRAY_SIZE(tests))

	struct thread threadv[NUM_TOTAL];
	unsigned n=0;
	unsigned test_index=0;
	size_t i;
	int err = 0;

	memset(threadv, 0, sizeof(threadv));

	(void)re_fprintf(stderr, "multithread test: %u testcases in parallel"
			 " with %d repeats (total %u threads): ",
			 ARRAY_SIZE(tests), NUM_REPEAT, NUM_TOTAL);

	for (i=0; i<ARRAY_SIZE(threadv); i++) {

		unsigned ti = (test_index++ % ARRAY_SIZE(tests));

		threadv[i].test = &tests[ti];
		threadv[i].err = -1;           /* error not set */

		err = pthread_create(&threadv[i].tid, NULL,
				     thread_handler, (void *)&threadv[i]);
		if (err) {
			DEBUG_WARNING("pthread_create failed (%m)\n", err);
			break;
		}

		++n;
	}

	for (i=0; i<ARRAY_SIZE(threadv); i++) {

		pthread_join(threadv[i].tid, NULL);
	}

	for (i=0; i<ARRAY_SIZE(threadv); i++) {

		if (threadv[i].err != 0) {
			re_printf("%u failed: %-30s  [%d] [%m]\n", i,
				  threadv[i].test->name,
				  threadv[i].err, threadv[i].err);
			err = threadv[i].err;
		}
	}

	if (err)
		return err;
	(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\n");

	return err;
}
#endif


int test_fuzzy(const char *name)
{
	struct mbuf *mb;
	uint16_t len;
	size_t i;
	int err = 0;
	static size_t n = 0;

	len = rand_u16();

	(void)re_fprintf(stderr, "\r%u: %u bytes    ", n++, len);

	mb = mbuf_alloc(len);
	if (!mb)
		return ENOMEM;

	rand_bytes(mb->buf, len);
	mb->end = len;

	if (name) {
		const struct ftest *test = find_ftest(name);
		if (!test) {
			(void)re_fprintf(stderr, "no such test: %s\n", name);
			err = ENOENT;
			goto out;
		}

		err = test->exec(mb);
	}
	else {
		for (i=0; i<ARRAY_SIZE(fuztests) && !err; i++) {
			mb->pos = 0;
			err = fuztests[i].exec(mb);
		}
	}

 out:
	mem_deref(mb);
	return err;
}


void test_listcases(void)
{
	size_t i, n;

	n = ARRAY_SIZE(tests);

	(void)re_printf("\n%u test cases:\n", n);

	for (i=0; i<(n+1)/2; i++) {

		(void)re_printf("    %-32s    %s\n",
				tests[i].name,
				(i+(n+1)/2) < n ? tests[i+(n+1)/2].name : "");
	}

	(void)re_printf("\n%u fuzzy test cases:\n", ARRAY_SIZE(fuztests));

	for (i=0; i<ARRAY_SIZE(fuztests); i++) {

		(void)re_printf("    %s\n", fuztests[i].name);
	}

	(void)re_printf("\n");
}


void test_hexdump_dual(FILE *f,
		       const void *ep, size_t elen,
		       const void *ap, size_t alen)
{
	const uint8_t *ebuf = ep;
	const uint8_t *abuf = ap;
	size_t i, j, len;
#define WIDTH 8

	if (!f || !ep || !ap)
		return;

	len = max(elen, alen);

	(void)re_fprintf(f, "\nOffset:   Expected (%zu bytes):    "
			 "   Actual (%zu bytes):\n", elen, alen);

	for (i=0; i < len; i += WIDTH) {

		(void)re_fprintf(f, "0x%04zx   ", i);

		for (j=0; j<WIDTH; j++) {
			const size_t pos = i+j;
			if (pos < elen) {
				bool wrong = pos >= alen;

				if (wrong)
					(void)re_fprintf(f, "\x1b[35m");
				(void)re_fprintf(f, " %02x", ebuf[pos]);
				if (wrong)
					(void)re_fprintf(f, "\x1b[;m");
			}
			else
				(void)re_fprintf(f, "   ");
		}

		(void)re_fprintf(f, "    ");

		for (j=0; j<WIDTH; j++) {
			const size_t pos = i+j;
			if (pos < alen) {
				bool wrong;

				if (pos < elen)
					wrong = ebuf[pos] != abuf[pos];
				else
					wrong = true;

				if (wrong)
					(void)re_fprintf(f, "\x1b[33m");
				(void)re_fprintf(f, " %02x", abuf[pos]);
				if (wrong)
					(void)re_fprintf(f, "\x1b[;m");
			}
			else
				(void)re_fprintf(f, "   ");
		}

		(void)re_fprintf(f, "\n");
	}

	(void)re_fprintf(f, "\n");
}


static void oom_watchdog_timeout(void *arg)
{
	int *err = arg;

	*err = ENOMEM;

	re_cancel();
}


int re_main_timeout(uint32_t timeout_ms)
{
	struct tmr tmr;
	int err = 0;

	tmr_init(&tmr);

	tmr_start(&tmr, timeout_ms, oom_watchdog_timeout, &err);
	(void)re_main(NULL);

	tmr_cancel(&tmr);
	return err;
}