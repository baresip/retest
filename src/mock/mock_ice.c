/* A "Mock" ICE endpoint */

#include <re.h>
#include <rew.h>
#include "test.h"


#define DEBUG_MODULE "mock/icepeer"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void destructor(void *arg)
{
	struct fake_remote *fake = arg;

	mem_deref(fake->rpwd);
	mem_deref(fake->rufrag);
	mem_deref(fake->lpwd);
	mem_deref(fake->lufrag);
	mem_deref(fake->us);
}


int fake_remote_alloc(struct fake_remote **fakep, struct trice *icem,
		      bool controlling,
		      const char *lufrag, const char *lpwd,
		      const char *rufrag, const char *rpwd)
{
	struct fake_remote *fake;
	int err = 0;

	if (!fakep || !lufrag || !lpwd || !rufrag || !rpwd)
		return EINVAL;

	fake = mem_zalloc(sizeof(*fake), destructor);
	if (!fake)
		return ENOMEM;

	fake->icem = icem;

	sa_set_str(&fake->addr, "127.0.0.1", 0);

	err = udp_listen(&fake->us, &fake->addr, NULL, NULL);
	if (err)
		goto out;

	err = udp_local_get(fake->us, &fake->addr);
	if (err)
		goto out;

	fake->controlling = controlling;
	err |= str_dup(&fake->lufrag, lufrag);
	err |= str_dup(&fake->lpwd, lpwd);
	err |= str_dup(&fake->rufrag, rufrag);
	err |= str_dup(&fake->rpwd, rpwd);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(fake);
	else
		*fakep = fake;

	return err;
}


/*
 * send from REMOTE to LOCAL
 *
 * Destination is "LCAND"
 */
int fake_remote_send_connectivity_check(struct fake_remote *fake,
					struct ice_lcand *lcand,
					const char *target_pwd, bool use_cand)
{
	char username[64];
	uint32_t prio_prflx;
	uint16_t ctrl_attr;
	uint8_t tid[STUN_TID_SIZE];
	struct mbuf *mb = mbuf_alloc(256);
	uint64_t tiebrk = rand_u64();
	int err = 0;

	if (!fake || !lcand || !target_pwd)
		return EINVAL;

	if (re_snprintf(username, sizeof(username), "%s:%s",
			fake->rufrag, fake->lufrag) < 0)
		return ENOMEM;

	/* PRIORITY and USE-CANDIDATE */
	prio_prflx = ice_cand_calc_prio(ICE_CAND_TYPE_PRFLX, 0,
					lcand->attr.compid);

	if (fake->controlling)
		ctrl_attr = STUN_ATTR_CONTROLLING;
	else
		ctrl_attr = STUN_ATTR_CONTROLLED;

	rand_bytes(tid, sizeof(tid));
	err = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
			      tid, NULL,
			      (void *)target_pwd, str_len(target_pwd), true,
			      0x00, 4,
			      STUN_ATTR_USERNAME, username,
			      STUN_ATTR_PRIORITY, &prio_prflx,
			      ctrl_attr, &tiebrk,
			      STUN_ATTR_USE_CAND,
			      use_cand ? &use_cand : 0);
	if (err)
		goto out;

	mb->pos = 0;
	err = udp_send(fake->us, &lcand->attr.addr, mb);

 out:
	mem_deref(mb);
	return err;
}


int fake_remote_reply(struct fake_remote *fake, struct ice_lcand *lcand,
		      const struct stun_msg *req,
		      uint32_t attrc, ...)
{
	struct mbuf *mb = NULL;
	int err = ENOMEM;
	va_list ap;

	if (!fake || !lcand || !req)
		return EINVAL;

	mb = mbuf_alloc(256);
	if (!mb)
		goto out;

	va_start(ap, attrc);
	mb->pos = 0;
	err = stun_msg_vencode(mb, stun_msg_method(req),
			       STUN_CLASS_SUCCESS_RESP,
			       stun_msg_tid(req), NULL,
			       /* NOTE: use local password: */
			       (void *)fake->lpwd, str_len(fake->lpwd),
			       true, 0x00, attrc, ap);
	va_end(ap);
	if (err)
		goto out;

	mb->pos = 0;
	err = udp_send(fake->us, &lcand->attr.addr, mb);

 out:
	mem_deref(mb);

	return err;
}


int fake_remote_ereply(struct fake_remote *fake, struct ice_lcand *lcand,
		       const struct stun_msg *req,
		       uint16_t scode, const char *reason,
		       uint32_t attrc, ...)
{
	struct stun_errcode ec;
	struct mbuf *mb = NULL;
	int err = ENOMEM;
	va_list ap;

	if (!fake || !lcand || !req || !scode || !reason)
		return EINVAL;

	mb = mbuf_alloc(256);
	if (!mb)
		goto out;

	ec.code = scode;
	ec.reason = (char *)reason;

	va_start(ap, attrc);
	mb->pos = 0;
	err = stun_msg_vencode(mb, stun_msg_method(req), STUN_CLASS_ERROR_RESP,
			       stun_msg_tid(req), &ec,
			       (void *)fake->lpwd, str_len(fake->lpwd),
			       true, 0x00, attrc, ap);
	va_end(ap);
	if (err)
		goto out;

	mb->pos = 0;
	err = udp_send(fake->us, &lcand->attr.addr, mb);

 out:
	mem_deref(mb);

	return err;
}
