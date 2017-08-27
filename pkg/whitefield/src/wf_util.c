#define	_WF_UTIL_C_

#include <string.h>
#include "whitefield.h"
#include "commline.h"

#include "net/ieee802154.h"

extern void sl_handle_cmd(msg_buf_t *mbuf);
extern uint16_t wf_nodeid;	//originally defined in cpu/native/startup.c
uint16_t wf_get_nodeid(void)
{
	return wf_nodeid;
}

int wf_get_longaddr(uint8_t *value, unsigned int val_len)
{
	return cl_get_id2longaddr(wf_nodeid, value, val_len);
}

int wf_init(void)
{
	if(cl_init(CL_ATTACHQ)!= CL_SUCCESS) {
		ERROR("Failure attaching to commline\n");
		return -1;
	}
	return 0;
}

int wf_send_pkt(const uint8_t *dst, const uint8_t *buf, const unsigned len)
{
	DEFINE_MBUF(mbuf);
	mbuf->len = len;
	memcpy(mbuf->buf, buf, len);
	mbuf->src_id = wf_nodeid;
	mbuf->dst_id = cl_get_longaddr2id(dst);

	INFO("SEND src:%0x dst:%0x len:%d\n", mbuf->src_id, mbuf->dst_id, mbuf->len);
	if(CL_SUCCESS != cl_sendto_q(MTYPE(AIRLINE, CL_MGR_ID), mbuf, mbuf->len + sizeof(msg_buf_t))) {
		//TODO mac_call_sent_callback(sent, ptr, MAC_TX_ERR_FATAL, 3);
	}
	return 0;
}

int wf_recv_pkt(wf_pkt_t *pkt)
{
	DEFINE_MBUF(mbuf);

	cl_recvfrom_q(MTYPE(STACKLINE, wf_nodeid), mbuf, sizeof(mbuf_buf), 0);
	if(!mbuf->len) {
		return 0;
	}
	INFO("RECV src:%x dst:%x len:%d flags:%x\n",
			mbuf->src_id, mbuf->dst_id, mbuf->len, mbuf->flags);
	if(mbuf->len >= sizeof(pkt->buf)) {
		ERROR("How can mbuflen(%d) be greater than bufsize:%d?!\n", 
				mbuf->len, sizeof(pkt->buf));
		return 0;
	}
	if(mbuf->flags & MBUF_IS_CMD) {
		sl_handle_cmd(mbuf);
		cl_sendto_q(MTYPE(MONITOR, CL_MGR_ID), mbuf, mbuf->len+sizeof(msg_buf_t));
		return 0;
	}
	memcpy(pkt->buf, mbuf->buf, mbuf->len);
	pkt->len = mbuf->len;
	cl_get_id2longaddr(mbuf->src_id, pkt->src, sizeof(pkt->src));
	cl_get_id2longaddr(mbuf->dst_id, pkt->dst, sizeof(pkt->dst));
	pkt->rssi = mbuf->info.sig.rssi;
	pkt->lqi = mbuf->info.sig.lqi;
	if(mbuf->flags & MBUF_IS_ACK) {
		//mac_handle_ack(mbuf);	//TODO
		return 0;
	}
	return mbuf->len;
}

