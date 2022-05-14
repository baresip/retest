/**
 * @file remain.c Testcode for re main loop
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "remain"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct data {
	thrd_t tid;
	mtx_t mutex;
	bool thread_started;
	bool thread_exited;
	unsigned tmr_called;
	int err;
};


static void tmr_handler(void *arg)
{
	struct data *data = arg;
	int err = 0;

	mtx_lock(&data->mutex);

	/* verify that timer is called from the new thread */
	TEST_ASSERT(0 != thrd_equal(data->tid, thrd_current()));

	++data->tmr_called;

 out:
	if (err)
		data->err = err;

	mtx_unlock(&data->mutex);

	re_cancel();
}


static int thread_handler(void *arg)
{
	struct data *data = arg;
	struct tmr tmr;
	int err;

	data->thread_started = true;

	tmr_init(&tmr);

	err = re_thread_init();
	if (err) {
		DEBUG_WARNING("re thread init: %m\n", err);
		data->err = err;
		return 0;
	}

	err = re_thread_init();
	TEST_EQUALS(EALREADY, err);

	tmr_start(&tmr, 1, tmr_handler, data);

	/* run the main loop now */
	err = re_main(NULL);

out:
	if (err) {
		data->err = err;
	}
	tmr_cancel(&tmr);

	/* cleanup */
	tmr_debug();
	re_thread_close();

	data->thread_exited = true;

	return 0;
}


static int test_remain_thread(void)
{
	struct data data;
	int i, err;

	memset(&data, 0, sizeof(data));

	mtx_init(&data.mutex, mtx_plain);

	err = thrd_create(&data.tid, thread_handler, &data);
	if (err)
		return err;

	/* wait for timer to be called */
	for (i=0; i<500; i++) {

		mtx_lock(&data.mutex);

		if (data.tmr_called || data.err) {
			mtx_unlock(&data.mutex);
			break;
		}

		mtx_unlock(&data.mutex);

		sys_msleep(1);
	}

	/* wait for thread to end */
	thrd_join(data.tid, NULL);

	if (data.err)
		return data.err;

	TEST_ASSERT(data.thread_started);
	TEST_ASSERT(data.thread_exited);
	TEST_EQUALS(1, data.tmr_called);
	TEST_EQUALS(0, data.err);

 out:
	return err;
}


int test_remain(void)
{
	int err = 0;

	err = test_remain_thread();
	if (err)
		return err;

	return err;
}
