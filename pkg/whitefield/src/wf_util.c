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
	int ret = cl_get_id2longaddr(wf_nodeid, value, val_len);
//	value[0] ^= 0x2;
	return ret;
}

int wf_init(void)
{
	if(cl_init(MTYPE(STACKLINE, wf_nodeid), CL_ATTACHQ)!= CL_SUCCESS) {
		ERROR("Failure attaching to commline\n");
		return -1;
	}
	return 0;
}

int wf_send_pkt(const uint8_t *dst, const uint8_t *buf, const unsigned len)
{
	struct timeval tv;
	DEFINE_MBUF(mbuf);
	mbuf->len = len;
	memcpy(mbuf->buf, buf, len);
	mbuf->src_id = wf_nodeid;
	mbuf->dst_id = cl_get_longaddr2id(dst);

	gettimeofday(&tv, NULL);
	INFO("SEND (%ld:%ld) src:%0x dst:%0x len:%d totlen:%d sizeof:%d\n", 
		tv.tv_sec, tv.tv_usec,
		mbuf->src_id, mbuf->dst_id, mbuf->len, mbuf->len + sizeof(msg_buf_t),
        (int)sizeof(msg_buf_t));
#if 0
	static int send_cnt=0;
	send_cnt++;
	PRINT_HEX(mbuf->buf, mbuf->len, "sent %d, len=%d\n", send_cnt, mbuf->len);
#endif
	if(CL_SUCCESS != cl_sendto_q(MTYPE(AIRLINE, CL_MGR_ID), mbuf, mbuf->len + sizeof(msg_buf_t))) {
		//TODO mac_call_sent_callback(sent, ptr, MAC_TX_ERR_FATAL, 3);
	}
	return 0;
}

int wf_recv_pkt(wf_pkt_t *pkt)
{
	struct timeval tv;
	DEFINE_MBUF(mbuf);

	cl_recvfrom_q(MTYPE(STACKLINE, wf_nodeid), mbuf, sizeof(mbuf_buf), 0);
	if(!mbuf->len) {
		return 0;
	}
	gettimeofday(&tv, NULL);
	INFO("RECV (%ld:%ld) src:%x dst:%x len:%d flags:%x\n",
			tv.tv_sec, tv.tv_usec,
			mbuf->src_id, mbuf->dst_id, mbuf->len, mbuf->flags);
	if(mbuf->len >= sizeof(pkt->buf)) {
		ERROR("How can mbuflen(%d) be greater than bufsize:%d?!\n", 
				mbuf->len, sizeof(pkt->buf));
		return 0;
	}
	if(mbuf->flags & MBUF_IS_CMD) {
#if 1
		//Hack Alert!! Notice that the foll condn will never be true
		//This condition had to be added so that cmd_* function are linked in the 
		//binary. Linker decides that cmd_* functions are never called from 
		//any other place and optimizes out! But I need these functions to be 
		//loaded dynamically using dlsym(). Using this check i sort of fool linker 
		//into believing that the function is called, but the wrapping cond will 
		//never be true.
		if(mbuf->len == 0xdead && mbuf->len == 0xc0de) {
			extern int cmd_rtsize(uint16_t, char *, int);
			cmd_rtsize(0xbabe, NULL, 0xcafe);
		}
#endif
		sl_handle_cmd(mbuf);
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

