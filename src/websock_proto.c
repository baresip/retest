/**
 * @file websock_proto.c Websockets Subprotocol Testcode
 */

#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_websock_proto"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct test {
	bool upgrade_only;
	struct websock *ws;
	struct websock_conn *wc_cli;
	struct websock_conn *wc_srv;
	uint32_t n_estab_cli;
	uint32_t n_recv_cli;
	uint32_t n_recv_srv;
	int err;
};

static const char test_payload[]     = "hello websockets proto";
static const char custom_useragent[] = "Retest v0.1";
static const char proto[]	     = "sip";

static void abort_test(struct test *t, int err)
{
	t->err = err;
	re_cancel();
}


static void done(struct test *t)
{
	t->wc_cli = mem_deref(t->wc_cli);
	t->wc_srv = mem_deref(t->wc_srv);

	websock_shutdown(t->ws);
}


static void srv_websock_recv_handler(const struct websock_hdr *hdr,
				     struct mbuf *mb, void *arg)
{
	struct test *test = arg;
	int err;

	test->n_recv_srv++;

	if (test->upgrade_only) {
		return;
	}

	/* ECHO */
	err = websock_send(test->wc_srv, hdr->opcode,
			   "%b", mbuf_buf(mb), mbuf_get_left(mb));
	if (err)
		abort_test(test, err);
}


static void srv_websock_close_handler(int err, void *arg)
{
	struct test *test = arg;
	(void)test;
	(void)err;
}


static void websock_shutdown_handler(void *arg)
{
	abort_test(arg, 0);
}


static void http_req_handler(struct http_conn *conn,
			     const struct http_msg *msg, void *arg)
{
	struct test *test = arg;
	int err;

	TEST_ASSERT(http_msg_hdr_has_value(msg, HTTP_HDR_USER_AGENT,
					   custom_useragent));

	TEST_ASSERT(http_msg_hdr_has_value(
		msg, HTTP_HDR_SEC_WEBSOCKET_PROTOCOL, proto));

	err = websock_accept_proto(&test->wc_srv, proto, test->ws, conn, msg,
			     0, srv_websock_recv_handler,
			     srv_websock_close_handler, test);
 out:
	if (err)
		abort_test(test, err);
}


static void cli_websock_estab_handler(void *arg)
{
	struct test *test = arg;
	int err;

	test->n_estab_cli++;

	err = websock_send(test->wc_cli, WEBSOCK_TEXT, test_payload);
	if (err)
		abort_test(test, err);
}


static void cli_websock_recv_handler(const struct websock_hdr *hdr,
				     struct mbuf *mb, void *arg)
{
	struct test *test = arg;
	int err = 0;

	test->n_recv_cli++;

	TEST_EQUALS(WEBSOCK_TEXT, hdr->opcode);

	TEST_STRCMP(test_payload, strlen(test_payload),
		    mbuf_buf(mb), mbuf_get_left(mb));

	done(test);

 out:
	if (err)
		abort_test(test, err);
}


static void cli_websock_close_handler(int err, void *arg)
{
	struct test *test = arg;
	(void)test;
	(void)err;

	/* translate error code */
	if (err) {
		abort_test(test, ENOMEM);
	}
}


static void upgrade_resp_handler(int err, const struct http_msg *msg,
				 void *arg)
{
	(void)arg;

	TEST_ERR(err);
	TEST_ASSERT(
		http_msg_hdr_has_value(msg, HTTP_HDR_UPGRADE, "websocket"));
	TEST_ASSERT(http_msg_hdr_has_value(
		msg, HTTP_HDR_SEC_WEBSOCKET_PROTOCOL, proto));
out:
	abort_test(arg, err);
}


static int test_websock_loop_proto_upgrade_test(void)
{
	struct http_sock *httpsock = NULL;
	struct http_cli *http_cli = NULL;
	struct http_req *req = NULL;
	struct dnsc *dnsc = NULL;
	struct sa srv, dns;
	struct test test;
	char uri[256];
	int err = 0;

	memset(&test, 0, sizeof(test));
	test.upgrade_only = true;

	err |= sa_set_str(&srv, "127.0.0.1", 0);
	err |= sa_set_str(&dns, "127.0.0.1", 53);    /* note: unused */
	if (err)
		goto out;

	err = http_listen(&httpsock, &srv, http_req_handler, &test);
	if (err)
		goto out;

	err = tcp_sock_local_get(http_sock_tcp(httpsock), &srv);
	if (err)
		goto out;

	err = dnsc_alloc(&dnsc, NULL, &dns, 1);
	if (err)
		goto out;

	err = http_client_alloc(&http_cli, dnsc);
	if (err)
		goto out;

	err = websock_alloc(&test.ws, websock_shutdown_handler, &test);
	if (err)
		goto out;

	(void)re_snprintf(uri, sizeof(uri),
			  "http://127.0.0.1:%u/", sa_port(&srv));

	/* Test upgrade */
	err = http_request(&req, http_cli, "GET", uri, upgrade_resp_handler,
			   NULL, &test,
			   "Upgrade: websocket\r\n"
			   "Connection: upgrade\r\n"
			   "Sec-WebSocket-Key: xFxowHzwiXSLs/M1cB+QPw==\r\n"
			   "Sec-WebSocket-Version: 13\r\n"
			   "Sec-WebSocket-Protocol: %s\r\n"
			   "User-Agent: Retest v0.1\r\n"
			   "\r\n", proto);
	TEST_ERR(err);

	err = re_main_timeout(500);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		goto out;
	}

 out:
	mem_deref(httpsock);
	mem_deref(test.ws);
	mem_deref(test.wc_srv);
	mem_deref(http_cli);
	mem_deref(req);
	mem_deref(dnsc);

	return err;
}


static int test_websock_loop_proto(void)
{
	struct http_sock *httpsock = NULL;
	struct http_cli *http_cli = NULL;
	struct dnsc *dnsc = NULL;
	struct sa srv, dns;
	struct test test;
	char uri[256];
	int err = 0;

	memset(&test, 0, sizeof(test));

	err |= sa_set_str(&srv, "127.0.0.1", 0);
	err |= sa_set_str(&dns, "127.0.0.1", 53);    /* note: unused */
	if (err)
		goto out;

	err = http_listen(&httpsock, &srv, http_req_handler, &test);
	if (err)
		goto out;

	err = tcp_sock_local_get(http_sock_tcp(httpsock), &srv);
	if (err)
		goto out;

	err = dnsc_alloc(&dnsc, NULL, &dns, 1);
	if (err)
		goto out;

	err = http_client_alloc(&http_cli, dnsc);
	if (err)
		goto out;

	err = websock_alloc(&test.ws, websock_shutdown_handler, &test);
	if (err)
		goto out;

	(void)re_snprintf(uri, sizeof(uri),
			  "http://127.0.0.1:%u/", sa_port(&srv));

	err = websock_connect_proto(&test.wc_cli, proto, test.ws,
			      http_cli, uri, 0,
			      cli_websock_estab_handler,
			      cli_websock_recv_handler,
			      cli_websock_close_handler, &test,
			      "User-Agent: %s\r\n", custom_useragent);
	TEST_ERR(err);

	err = re_main_timeout(500);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		goto out;
	}

	/* verify results after traffic is successfully done */
	TEST_EQUALS(1, test.n_estab_cli);
	TEST_EQUALS(1, test.n_recv_cli);
	TEST_EQUALS(1, test.n_recv_srv);

 out:
	mem_deref(httpsock);
	mem_deref(test.wc_cli);
	mem_deref(test.ws);
	mem_deref(test.wc_srv);
	mem_deref(http_cli);
	mem_deref(dnsc);

	return err;
}


int test_websock_proto(void)
{
	int err = 0;

	err |= test_websock_loop_proto();
	err |= test_websock_loop_proto_upgrade_test();

	return err;
}
