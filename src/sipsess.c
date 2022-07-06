/**
 * @file sipsess.c SIP Session regression testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_sipsess"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct test {
	struct sip *sip;
	struct sipsess_sock *sock;
	struct sipsess *a;
	struct sipsess *b;
	bool estab_a;
	bool estab_b;
	bool answr_a;
	bool answr_b;
	bool progr_a;
	bool progr_b;
	bool offer_a;
	bool offer_b;
	enum rel100_mode rel100_a;
	enum rel100_mode rel100_b;
	bool req_received_a;
	bool req_received_b;
	bool sup_received_a;
	bool sup_received_b;
	struct mbuf *desc;
	bool blind_transfer;
	uint16_t altaddr_port;
	int err;
};


static void stop_test(void)
{
	re_cancel();
}


static void abort_test(struct test *test, int err)
{
	test->err = err;
	re_cancel();
}


static void exit_handler(void *arg)
{
	(void)arg;
	re_cancel();
}


static int desc_handler(struct mbuf **descp, const struct sa *src,
				const struct sa *dst, void *arg)
{
	struct test *test = arg;
	(void)src;
	(void)dst;

	test->desc = mbuf_alloc(1);
	if (!test->desc)
		return ENOMEM;

	*descp = test->desc;
	return 0;
}


static int offer_handler_a(struct mbuf **descp, const struct sip_msg *msg,
			   void *arg)
{
	struct test *test = arg;
	(void)descp;
	(void)msg;

	test->offer_a = true;
	return 0;
}


static int offer_handler_b(struct mbuf **descp, const struct sip_msg *msg,
			   void *arg)
{
	struct test *test = arg;
	(void)descp;
	(void)msg;

	test->offer_b = true;
	return 0;
}


static int answer_handler_a(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;

	test->sup_received_a = sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED,
						     "100rel");
	test->req_received_a = sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE,
						     "100rel");

	test->answr_a = true;
	return 0;
}


static int answer_handler_b(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;

	test->answr_b = true;
	return 0;
}


static void progr_handler_a(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;

	test->progr_a = true;
}


static void estab_handler_a(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;

	(void)msg;

	test->estab_a = true;

	if (test->estab_b)
		stop_test();
}


static void estab_handler_b(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;

	(void)msg;

	test->estab_b = true;

	if (test->estab_a)
		stop_test();
}


static void close_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;

	(void)err;
	(void)msg;
	(void)arg;

	abort_test(test, err ? err : ENOMEM);
}

static void conn_handler_100rel(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	char *desc = test->rel100_b == REL100_REQUIRED ?
		     "Require: 100rel\r\n" : "";
	(void)arg;

	test->sup_received_b = sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED,
						     "100rel");
	test->req_received_b = sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE,
						     "100rel");

	(void)sipsess_accept(&test->b, test->sock, msg, 180, "RINGING",
			     test->rel100_b, "b", "application/sdp",
			     NULL, NULL, NULL, false, offer_handler_b,
			     answer_handler_b, estab_handler_b, NULL, NULL,
			     close_handler, test, desc);
}


static void conn_handler(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	int err;

	(void)arg;

	err = sipsess_accept(&test->b, test->sock, msg, 200, "OK",
			     test->rel100_b, "b", "application/sdp",
			     NULL, NULL, NULL, false, offer_handler_b,
			     answer_handler_b, estab_handler_b, NULL, NULL,
			     close_handler, test, NULL);
	if (err) {
		abort_test(test, err);
	}
}


static void conn_transfer_handler(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	int err = 0;

	if (test->blind_transfer) {
		conn_handler(msg, arg);
	}
	else {
		err = sip_replyf(test->sip, msg, 302, "Moved Temporarily",
			"Contact: \"alt retest\" "
			"<sip:127.0.0.1:%u>\r\n\r\n", test->altaddr_port);
		if (err) {
			abort_test(test, err);
		}
	}

	return;
}


static void redirect_handler(const struct sip_msg *msg, const char *uri,
	void *arg)
{
	struct test *test = arg;

	(void) msg;
	(void) uri;

	test->blind_transfer = true;
}


int test_sipsess(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	if (err)
		goto out;

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	if (err)
		goto out;

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	if (err)
		goto out;

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler, &test);
	if (err)
		goto out;

	err = str_x64dup(&callid, rand_u64());
	if (err)
		goto out;

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test, NULL);
	mem_deref(callid);
	if (err)
		goto out;

	err = re_main_timeout(200);
	if (err)
		goto out;

	if (test.err) {
		err = test.err;
		goto out;
	}

	/* okay here -- verify */
	TEST_ASSERT(test.estab_a);
	TEST_ASSERT(test.estab_b);
	TEST_ASSERT(test.desc);
	TEST_ASSERT(test.answr_a);
	TEST_ASSERT(!test.offer_b);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_blind_transfer(void)
{
	struct test test;
	struct sa laddr, altaddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_transfer_handler,
		&test);
	TEST_ERR(err);

	(void)sa_set_str(&altaddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &altaddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &altaddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	test.altaddr_port = sa_port(&altaddr);

	err = str_x64dup(&callid, rand_u64());
	if (err)
		goto out;

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test, NULL);
	mem_deref(callid);
	TEST_ERR(err);

	err = sipsess_set_redirect_handler(test.a, redirect_handler);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	TEST_ASSERT(test.blind_transfer);
	TEST_ASSERT(test.estab_a);
	TEST_ASSERT(test.estab_b);
	TEST_ASSERT(test.desc);
	TEST_ASSERT(test.answr_a);
	TEST_ASSERT(!test.offer_b);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}

int test_sipsess_100rel_caller_require(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_REQUIRED;
	test.rel100_b = REL100_ENABLED;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler_100rel,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL, NULL,
			      close_handler, &test,
			      "Require: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(400);

	err = sipsess_answer(test.b, 200, "Answering", NULL, NULL);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	TEST_ASSERT(test.estab_a);
	TEST_ASSERT(test.estab_b);
	TEST_ASSERT(test.desc);
	TEST_ASSERT(test.answr_a);
	TEST_ASSERT(!test.offer_b);
	TEST_ASSERT(test.progr_a);
	TEST_ASSERT(test.req_received_b);
	TEST_ASSERT(!test.sup_received_b);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_100rel_supported(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler_100rel,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL, NULL,
			      close_handler, &test,
			      "Supported: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);

	err = sipsess_answer(test.b, 200, "Answering", NULL, NULL);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	TEST_ASSERT(test.estab_a);
	TEST_ASSERT(test.estab_b);
	TEST_ASSERT(test.desc);
	TEST_ASSERT(test.answr_a);
	TEST_ASSERT(!test.offer_b);
	TEST_ASSERT(test.progr_a);
	TEST_ASSERT(test.sup_received_b);
	TEST_ASSERT(!test.req_received_b);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_100rel_420(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_REQUIRED;
	test.rel100_b = REL100_DISABLED;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler_100rel,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test,
			      "Require: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	/* okay here -- verify */
	TEST_ASSERT(!test.b);
	TEST_ASSERT(!test.estab_a);
	TEST_ASSERT(!test.estab_b);
	TEST_ASSERT(test.desc);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_100rel_421(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_DISABLED;
	test.rel100_b = REL100_REQUIRED;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler_100rel,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test, NULL);
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	/* okay here -- verify */
	TEST_ASSERT(!test.b);
	TEST_ASSERT(!test.estab_a);
	TEST_ASSERT(!test.estab_b);
	TEST_ASSERT(test.desc);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}
