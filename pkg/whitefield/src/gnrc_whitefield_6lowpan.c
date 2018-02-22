/**
 * @{
 * @ingroup     net
 * @file
 * @brief       Glue for Whitefield-Framework
 *
 * @author      Rahul Jadhav <nyrahul@gmail.com>
 * @}
 */

#include <assert.h>
#include <errno.h>
#include <sys/time.h>

#include "msg.h"
#include "net/gnrc.h"
#include "net/gnrc/nettype.h"
#include "net/ieee802154.h"
#ifdef MODULE_NETSTATS_L2
#include "net/netstats.h"
#endif

#include "whitefield.h"

#if defined(MODULE_OD) && ENABLE_DEBUG
#include "od.h"
#endif

#define WF_NETAPI_MSG_QUEUE_SIZE   (8U)
#define WF_PRIO                    (THREAD_PRIORITY_MAIN - 1)
#define	WF_EVENT_RX_DONE			20000

wf_pkt_t g_wf_pkt;
kernel_pid_t g_wf_pid;
static char g_stack[(THREAD_STACKSIZE_DEFAULT + DEBUG_EXTRA_STACKSIZE)];
//static char g_stack_recvwf[(THREAD_STACKSIZE_DEFAULT + DEBUG_EXTRA_STACKSIZE)];
#ifdef MODULE_NETSTATS_L2
static netstats_t g_l2_stats;
#endif

static void handle_raw_sixlowpan(wf_pkt_t *inbuf)
{
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, inbuf->buf,
            inbuf->len,
            GNRC_NETTYPE_SIXLOWPAN);

    if(!pkt) {
        ERROR("whitefield: no space left in packet buffer.\n");
        return;
    }

    /* create netif header */
    gnrc_pktsnip_t *netif_hdr;
    netif_hdr = gnrc_pktbuf_add(NULL, NULL,
            sizeof(gnrc_netif_hdr_t) + (2 * sizeof(eui64_t)),
            GNRC_NETTYPE_NETIF);

    if (netif_hdr == NULL) {
        ERROR("no space left in packet buffer.\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

    gnrc_netif_hdr_init(netif_hdr->data, WF_L2ADDR_LEN, WF_L2ADDR_LEN);
    gnrc_netif_hdr_set_src_addr(netif_hdr->data, inbuf->src, WF_L2ADDR_LEN);
    gnrc_netif_hdr_set_dst_addr(netif_hdr->data, inbuf->dst, WF_L2ADDR_LEN);
    ((gnrc_netif_hdr_t *)netif_hdr->data)->if_pid = g_wf_pid;

    INFO("rcvd pkt from %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
            "of len %d\n",
            inbuf->src[0], inbuf->src[1], inbuf->src[2], inbuf->src[3], inbuf->src[4],
            inbuf->src[5], inbuf->src[6], inbuf->src[7], inbuf->len);
#if defined(MODULE_OD) && ENABLE_DEBUG
    od_hex_dump(inbuf->buf, inbuf->len, OD_WIDTH_DEFAULT);
#endif

    LL_APPEND(pkt, netif_hdr);

    /* throw away packet if no one is interested */
    if (!gnrc_netapi_dispatch_receive(pkt->type, GNRC_NETREG_DEMUX_CTX_ALL, pkt)) {
        ERROR("unable to forward packet of type %i\n", pkt->type);
        gnrc_pktbuf_release(pkt);
    }
}

static int _send(gnrc_pktsnip_t *pkt)
{
	uint8_t _sendbuf[WF_MAX_PKT_SZ];

    if (pkt == NULL) {
        ERROR("_send: pkt was NULL\n");
        return -EINVAL;
    }

    gnrc_netif_hdr_t *netif_hdr;
    gnrc_pktsnip_t *payload = pkt->next;
    uint8_t *dst;

    uint8_t *buf = _sendbuf;
    unsigned len = 0;

    if (pkt->type != GNRC_NETTYPE_NETIF) {
        ERROR("_send: first header is not generic netif header\n");
        return -EBADMSG;
    }

    netif_hdr = pkt->data;

    /* prepare destination address */
    if (netif_hdr->flags &
        (GNRC_NETIF_HDR_FLAGS_BROADCAST | GNRC_NETIF_HDR_FLAGS_MULTICAST)) {
        dst = NULL;
    }
    else {
        dst = gnrc_netif_hdr_get_dst_addr(netif_hdr);
    }

    /* prepare packet for sending */
    while (payload) {
		if(len+payload->size >= sizeof(_sendbuf)) {
			ERROR("--- READY TO CRASH len=%d size:%d sizeof(_sendbuf):%zu\n", 
					len, payload->size, sizeof(_sendbuf));
		}
		assert(len+payload->size<sizeof(_sendbuf));
        memcpy(buf, payload->data, payload->size);
        len += payload->size;
        buf +=  payload->size;
        payload = payload->next;
    }
	wf_send_pkt(dst, _sendbuf, len);

    gnrc_pktbuf_release(pkt);
#ifdef	MODULE_NETSTATS_L2
	g_l2_stats.tx_bytes += len;
	if(dst) {
		g_l2_stats.tx_unicast_count++;
	} else {
		g_l2_stats.tx_mcast_count++;
	}
#endif
    return 0;
}

static int _handle_set(gnrc_netapi_opt_t *_opt)
{
    int res = -ENOTSUP;
    uint8_t *value = _opt->data;

    switch (_opt->opt) {
        case NETOPT_SRC_LEN:
            assert(_opt->data_len == sizeof(uint16_t));
            res = sizeof(uint16_t);
            switch ((*(uint16_t *)value)) {
                case IEEE802154_SHORT_ADDRESS_LEN:
                    INFO("SHORT ADDRESS LEN set\n");
                    break;
                case IEEE802154_LONG_ADDRESS_LEN:
                    INFO("LONG ADDRESS LEN set\n");
                    break;
                default:
                    res = -EAFNOSUPPORT;
                    break;
            }
            break;
        default:
            break;
    }
    return res;
}

static int _handle_get(gnrc_netapi_opt_t *_opt)
{
    int res = -ENOTSUP;
    uint8_t *value = _opt->data;

    switch (_opt->opt) {
        case NETOPT_IPV6_IID:
        case NETOPT_ADDRESS_LONG:
			wf_get_longaddr(value, _opt->data_len);
            res = IEEE802154_LONG_ADDRESS_LEN;
            break;
        case NETOPT_ADDR_LEN:
        case NETOPT_SRC_LEN:
            assert(_opt->data_len == sizeof(uint16_t));
            *((uint16_t *)value) = IEEE802154_LONG_ADDRESS_LEN;
            res = sizeof(uint16_t);
            break;
		case NETOPT_MAX_PACKET_SIZE:
			assert(_opt->data_len >= 2);
			*((uint16_t*)value) = WF_MAX_FRAG_SZ;
			res = sizeof(uint16_t);
			break;
#ifdef MODULE_NETSTATS_L2
        case NETOPT_STATS:
            assert(_opt->data_len == sizeof(uintptr_t));
            *((netstats_t **)value) = &g_l2_stats;
            res = sizeof(uintptr_t);
            break;
#endif
#ifdef MODULE_GNRC
        case NETOPT_PROTO:
            assert(_opt->data_len == sizeof(gnrc_nettype_t));
            *((gnrc_nettype_t *)value) = GNRC_NETTYPE_SIXLOWPAN;
            res = sizeof(gnrc_nettype_t);
            break;
#endif
        default:
            break;
    }
    return res;
}

/**
 * @brief   Startup code and event loop of the gnrc_whitefield_6lowpan layer
 *
 * @return          never returns
 */
static void *_gnrc_whitefield_6lowpan_thread(void *args)
{
	struct timeval tv;
	(void)args;
#ifdef MODULE_NETSTATS_L2
    memset(&g_l2_stats, 0, sizeof(g_l2_stats));
#endif

    INFO("gnrc_whitefield_6lowpan: starting thread\n");

    g_wf_pid = thread_getpid();

    gnrc_netapi_opt_t *opt;
    int res;
    msg_t msg, reply, msg_queue[WF_NETAPI_MSG_QUEUE_SIZE];

    /* setup the message queue */
    msg_init_queue(msg_queue, WF_NETAPI_MSG_QUEUE_SIZE);

    /* register the device to the network stack*/
    gnrc_netif_add(thread_getpid());

    /* start the event loop */
    while (1) {
		gettimeofday(&tv, NULL);
//		INFO("blocking on msg_receive %ld:%ld\n", tv.tv_sec, tv.tv_usec);
        msg_receive(&msg);
        /* dispatch NETDEV and NETAPI messages */
		gettimeofday(&tv, NULL);
//		INFO("got msg msg_receive %ld:%ld\n", tv.tv_sec, tv.tv_usec);
        switch (msg.type) {
            case WF_EVENT_RX_DONE:
                {
					wf_pkt_t *pkt = msg.content.ptr;
                    INFO("wf recvd pkt=%d\n", pkt->len);
                    handle_raw_sixlowpan(pkt);
                    pkt->len = 0;
                    break;
                }
            case GNRC_NETAPI_MSG_TYPE_SND:
                _send(msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SET:
                /* read incoming options */
                opt = msg.content.ptr;
                /* set option for device driver */
                res = _handle_set(opt);
                INFO("SET received. opt=%s res:%i\n", netopt2str(opt->opt), res);
                /* send reply to calling thread */
                reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
                reply.content.value = (uint32_t)res;
                msg_reply(&msg, &reply);
                break;
            case GNRC_NETAPI_MSG_TYPE_GET:
                /* read incoming options */
                opt = msg.content.ptr;
                res = _handle_get(opt);
                //INFO("GET: opt=%s res:%i\n", netopt2str(opt->opt), res);
                /* send reply to calling thread */
                reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
                reply.content.value = (uint32_t)res;
                msg_reply(&msg, &reply);
                break;
            default:
                INFO("gnrc_whitefield_6lowpan: Unknown command %" PRIu16 "\n", msg.type);
                break;
        }
    }
    /* never reached */
    return NULL;
}

#define	WAIT_FOR_COND(COND, SLPTIME_MS)	\
	{\
		int loopcnt=0;\
		while(loopcnt++ < SLPTIME_MS) {\
			if(COND) break;\
			usleep(1000);\
		}\
		if(loopcnt>=SLPTIME_MS) {\
			ERROR("COND %s never reached. Behaviour Undefined!\n", #COND);\
		}\
	}
void *stackline_recvthread(void *args)
{
	msg_t m;
	wf_pkt_t *pkt=&g_wf_pkt;
	int sz;

	(void)args;
	WAIT_FOR_COND(g_wf_pid > 0, 1000);//Wait for other thread to start
	INFO("wf stackline_recvthread started g_wf_pid:%d\n", g_wf_pid);

	while(1) {
		sz = wf_recv_pkt(pkt);	//Blocking call
		if(!sz) continue;
		m.type = WF_EVENT_RX_DONE;
		m.content.ptr = pkt;
		if(!msg_send_int(&m, g_wf_pid)) {
			ERROR("msg send failed to internal q, possible lost intr\n");
			pkt->len=0;
		}
		WAIT_FOR_COND(pkt->len==0,1000);
	}
	return NULL;
}

void gnrc_whitefield_6lowpan_init(void)
{
	if(wf_get_nodeid() == 0xffff) {
		ERROR("Nodeid not passed white execution. -w <nodeid>\n");
		abort();
	}
	if(wf_init()) {
		ERROR("whitefield init failed\n");
		abort();
	}
    kernel_pid_t res = thread_create(g_stack, sizeof(g_stack), WF_PRIO,
                        THREAD_CREATE_STACKTEST,
                        _gnrc_whitefield_6lowpan_thread, NULL,
                        "WF NETAPI");
    assert(res > 0);
#if 0
    res = thread_create(g_stack_recvwf, sizeof(g_stack_recvwf), WF_PRIO,
					THREAD_CREATE_STACKTEST,
					stackline_recvthread, NULL,
					"WF RECV");
#endif
	INFO("Whitefield Inited. Nodeid=0x%x\n", wf_get_nodeid());
    (void)res;
}
