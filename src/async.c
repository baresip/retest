/**
 * @file async.c Testcode for re async
 *
 * Copyright (C) 2022 Sebastian Reimers
 */
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1

#ifndef WIN32
#include <netdb.h>
#endif

#include <string.h>
#include <re.h>
#include "test.h"

#define DEBUG_MODULE "async"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

struct test_cnt {
	int tests;
	int done;
};

struct test {
	char domain[128];
	struct sa sa;
	int err;
	int err_expected;
	struct test_cnt *cnt;
};

static int blocking_getaddr(void *arg)
{
	int err;
	struct test *test    = arg;
	struct addrinfo *res = NULL;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags	= AI_V4MAPPED | AI_ADDRCONFIG;


	/* Blocking */
	err = getaddrinfo(test->domain, NULL, &hints, &res);
	if (err)
		return EADDRNOTAVAIL;

	sa_set_sa(&test->sa, res->ai_addr);
	freeaddrinfo(res);

	return 0;
}


static void completed(int err, void *arg)
{
	struct test *test = arg;
	struct sa sa;

	if (err)
		goto out;

	err = re_thread_check();
	TEST_ERR(err);

	sa_set_str(&sa, "127.0.0.1", 0);
	if (!sa_cmp(&sa, &test->sa, SA_ADDR))
		err = EINVAL;

	TEST_ERR(err);

out:
	test->err = err;
	if (++test->cnt->done >= test->cnt->tests)
		re_cancel();
}


int test_async(void)
{
	int err;

	struct test_cnt cnt = {0, 0};

	struct test testv[] = {
		{"localhost", {.len = 0}, -1, 0, &cnt},
		{"test.notfound", {.len = 0}, -1, EADDRNOTAVAIL, &cnt}
	};

	cnt.tests = ARRAY_SIZE(testv);

	err = re_thread_async_init(2);
	TEST_ERR(err);

	for (size_t i = 0; i < ARRAY_SIZE(testv); i++) {
		err = re_thread_async(blocking_getaddr, completed, &testv[i]);
		TEST_ERR(err);
	}

	err = re_main_timeout(200);
	TEST_ERR(err);

	for (size_t i = 0; i < ARRAY_SIZE(testv); i++) {
		TEST_EQUALS(testv[i].err_expected, testv[i].err);
	}

out:
	re_thread_async_close();
	return err;
}
