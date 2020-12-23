/**
 * @file trace.c  Trace testcode
 */

#include <re.h>
#include "test.h"

static void test_loop(int count)
{
	int i;

	for (i=0; i < count; i++) {
		RE_TRACE_INSTANT_I("test", "Instant", i);
	}
}

int test_trace(void)
{
	int err;

	err = re_trace_init("test_trace.json");
	if (err)
		return err;

	RE_TRACE_PROCESS_NAME("retest");
	RE_TRACE_THREAD_NAME("test_trace");
	RE_TRACE_BEGIN("test", "Test Loop Start");

	test_loop(100);

	RE_TRACE_BEGIN("test", "Flush");
	err = re_trace_flush();
	if (err)
		return err;

	RE_TRACE_END("test", "Flush");

	test_loop(25);

	RE_TRACE_BEGIN_FUNC();
	err = re_trace_flush();
	if (err)
		return err;
	RE_TRACE_END_FUNC();

	RE_TRACE_END("test", "Test Loop End");

	err = re_trace_close();
	if (err)
		return err;

	/* Test TRACE after close - should do nothing */
	RE_TRACE_BEGIN("test", "test after close");

	return err;
}
