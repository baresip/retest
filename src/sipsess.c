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
	bool upd_a;
	bool upd_b;
	struct mbuf *desc;
	bool blind_transfer;
	uint16_t altaddr_port;
	int err;
};


const char sdp_a[] = "v=0\r\n"
		     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
		     "s=-\r\n"
		     "c=IN IP4 1.2.3.4\r\n"
		     "t=0 0\r\n"
		     "m=audio 49170 RTP/AVP 0 8 97\r\n"
		     "a=rtpmap:0 PCMU/8000\r\n"
		     "a=rtpmap:8 PCMA/8000\r\n"
		     "a=rtpmap:97 iLBC/8000\r\n"
		     "a=sendrecv\r\n"
		     "m=video 51372 RTP/AVP 31 32\r\n"
		     "a=rtpmap:31 H261/90000\r\n"
		     "a=rtpmap:32 MPV/90000\r\n"
		     "a=sendrecv\r\n";
const char sdp_b[] = "v=0\r\n"
		     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
		     "s=-\r\n"
		     "c=IN IP4 5.6.7.8\r\n"
		     "t=0 0\r\n"
		     "m=audio 49174 RTP/AVP 0\r\n"
		     "a=rtpmap:0 PCMU/8000\r\n"
		     "a=sendrecv\r\n"
		     "m=video 49170 RTP/AVP 32\r\n"
		     "a=rtpmap:32 MPV/90000\r\n"
		     "a=sendrecv\r\n";


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


static int offer_handler_update_a(struct mbuf **descp,
				   const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	struct mbuf *desc;
	int err = 0;
	(void)msg;

	if (!pl_strcmp(&msg->met, "UPDATE"))
		test->upd_a = true;

	desc = mbuf_alloc(sizeof(sdp_a));
	if (!desc) {
		err = ENOMEM;
		goto out;
	}
	err = mbuf_write_str(desc, sdp_a);
	if (err)
		goto out;
	mbuf_set_pos(desc, 0);
	*descp = desc;

out:
	test->offer_a = true;
	return err;
}


static int offer_handler_update_b(struct mbuf **descp,
				   const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	struct mbuf *desc;
	int err = 0;
	(void)msg;

	if (!pl_strcmp(&msg->met, "UPDATE"))
		test->upd_b = true;

	desc = mbuf_alloc(sizeof(sdp_b));
	if (!desc) {
		err = ENOMEM;
		goto out;
	}
	err = mbuf_write_str(desc, sdp_b);
	if (err)
		goto out;
	mbuf_set_pos(desc, 0);
	*descp = desc;

out:
	test->offer_b = true;
	return err;
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
	test->answr_a = true;

	test->sup_received_a = sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED,
						     "100rel");
	test->req_received_a = sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE,
						     "100rel");

	if (!pl_strcmp(&msg->cseq.met, "UPDATE")) {
		if (msg->scode < 200 || msg->scode > 299) {
			abort_test(test, msg->scode);
			return msg->scode;
		}
		re_cancel();
	}

	if (!pl_strcmp(&msg->met, "PRACK"))
		re_cancel();

	return 0;
}


static int answer_handler_b(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;
	test->answr_b = true;

	test->sup_received_b = sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED,
						     "100rel");
	test->req_received_b = sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE,
						     "100rel");

	if (!pl_strcmp(&msg->cseq.met, "UPDATE")) {
		if (msg->scode < 200 || msg->scode > 299) {
			abort_test(test, msg->scode);
			return msg->scode;
		}
		re_cancel();
	}


	if (!pl_strcmp(&msg->met, "PRACK"))
		re_cancel();

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

	re_cancel();
}


static void conn_handler_update(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	struct mbuf *desc;
	int err;
	char *hdrs = test->rel100_b == REL100_REQUIRED ?
		     "Require: 100rel\r\n" : "";
	(void)arg;

	test->sup_received_b = sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED,
						     "100rel");
	test->req_received_b = sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE,
						     "100rel");

	desc = mbuf_alloc(sizeof(sdp_b));
	if (!desc) {
		abort_test(test, ENOMEM);
		return;
	}
	err = mbuf_write_str(desc, sdp_b);
	if (err) {
		abort_test(test, err);
		return;
	}
	mbuf_set_pos(desc, 0);
	test->desc = desc;

	(void)sipsess_accept(&test->b, test->sock, msg, 183, "Progress",
			     test->rel100_b, "b", "application/sdp",
			     desc, NULL, NULL, false, offer_handler_update_b,
			     answer_handler_b, estab_handler_b, NULL, NULL,
			     close_handler, test, hdrs);
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

	err = re_main_timeout(200);
	TEST_ERR(err);

	err = sipsess_answer(test.b, 200, "Answering", NULL, NULL);
	TEST_ERR(err);

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
	TEST_ERR(err);

	err = sipsess_answer(test.b, 200, "Answering", NULL, NULL);
	TEST_ERR(err);

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


int test_sipsess_update_uac(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	struct mbuf *desc_a = NULL;
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

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler_update,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, NULL,
			      offer_handler_update_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test,
			      "Supported: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	desc_a = mbuf_alloc(sizeof(sdp_a));
	err = mbuf_write_str(desc_a, sdp_a);
	TEST_ERR(err);
	mbuf_set_pos(desc_a, 0);

	/* Wait for PRACK */
	err = re_main_timeout(200);
	TEST_ERR(err);

	err = sipsess_modify(test.a, desc_a);
	TEST_ERR(err);

	/* Wait for UPDATE */
	err = re_main_timeout(200);
	TEST_ERR(err);

	err = sipsess_answer(test.b, 200, "Answering", NULL, NULL);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	TEST_ASSERT(test.estab_a);
	TEST_ASSERT(test.estab_b);
	TEST_ASSERT(test.answr_a);
	TEST_ASSERT(test.answr_b);
	TEST_ASSERT(test.offer_a);
	TEST_ASSERT(test.offer_b);
	TEST_ASSERT(test.progr_a);
	TEST_ASSERT(test.upd_b);
	TEST_ASSERT(!test.upd_a);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	mem_deref(desc_a);
	mem_deref(test.desc);

	return err;
}


int test_sipsess_update_uas(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	struct mbuf *desc_b = NULL;
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

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler_update,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, NULL,
			      offer_handler_update_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test,
			      "Supported: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	desc_b = mbuf_alloc(sizeof(sdp_b));
	err = mbuf_write_str(desc_b, sdp_b);
	TEST_ERR(err);
	mbuf_set_pos(desc_b, 0);

	/* Wait for PRACK */
	err = re_main_timeout(200);
	TEST_ERR(err);

	err = sipsess_modify(test.b, desc_b);
	TEST_ERR(err);

	/* Wait for UPDATE */
	err = re_main_timeout(200);
	TEST_ERR(err);

	err = sipsess_answer(test.b, 200, "Answering", NULL, NULL);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	TEST_ASSERT(test.estab_a);
	TEST_ASSERT(test.estab_b);
	TEST_ASSERT(!test.answr_a);
	TEST_ASSERT(test.answr_b);
	TEST_ASSERT(test.offer_a);
	TEST_ASSERT(!test.offer_b);
	TEST_ASSERT(test.progr_a);
	TEST_ASSERT(test.upd_a);
	TEST_ASSERT(!test.upd_b);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	mem_deref(desc_b);
	mem_deref(test.desc);

	return err;
}
