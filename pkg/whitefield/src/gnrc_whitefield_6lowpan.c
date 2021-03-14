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

#define	WF_EVENT_RX_DONE			20000

static char g_stack[(THREAD_STACKSIZE_DEFAULT + DEBUG_EXTRA_STACKSIZE)];
static gnrc_netif_t _netif;
#ifdef MODULE_NETSTATS_L2
static netstats_t g_l2_stats;
#endif
static thread_t *_netif_thread;
static gnrc_nettype_t _nettype = GNRC_NETTYPE_SIXLOWPAN;

static gnrc_netif_t *_wf_netif = NULL;

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
    ((gnrc_netif_hdr_t *)netif_hdr->data)->if_pid = _wf_netif->pid;

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

static int _netdev_set(netdev_t *netdev, netopt_t opt,
                       const void *value, size_t value_len)
{
    int res=-ENOTSUP;

    (void)netdev;
    switch(opt) {
        case NETOPT_SRC_LEN:
            assert(value_len == sizeof(uint16_t));
            res = sizeof(uint16_t);
            switch ((*(uint16_t *)value)) {
                case IEEE802154_SHORT_ADDRESS_LEN:
                    INFO("SHORT ADDRESS LEN set\n");
                    break;
                case IEEE802154_LONG_ADDRESS_LEN:
                    INFO("LONG ADDRESS LEN set\n");
                    break;
				case NETOPT_PROTO:
					assert(value_len == sizeof(_nettype));
					memcpy(&_nettype, value, sizeof(_nettype));
					res = sizeof(_nettype);
					break;
                default:
                    res = -ENOTSUP;
                    break;
            }
            break;
        default:
            INFO("netdev_set not handled for opt=%d\n", opt);
            break;
    }

    return res;
}

static int _netdev_get(netdev_t *netdev, netopt_t opt,
                       void *v, size_t max_len)
{
    int res = -ENOTSUP;
    uint8_t *value = v;

    (void)netdev;
    switch (opt) {
        case NETOPT_IPV6_IID:
        case NETOPT_ADDRESS:
        case NETOPT_ADDRESS_LONG:
            assert(max_len == WF_L2ADDR_LEN);
			wf_get_longaddr(value, max_len);
            res = IEEE802154_LONG_ADDRESS_LEN;
            break;
        case NETOPT_ADDR_LEN:
        case NETOPT_SRC_LEN:
            assert(max_len == sizeof(uint16_t));
            *((uint16_t *)value) = IEEE802154_LONG_ADDRESS_LEN;
            res = sizeof(uint16_t);
            break;
		case NETOPT_MAX_PACKET_SIZE:
			assert(max_len >= 2);
			*((uint16_t*)value) = WF_MAX_FRAG_SZ;
			res = sizeof(uint16_t);
			break;
        case NETOPT_DEVICE_TYPE:
            assert(max_len == sizeof(uint16_t));
            *((uint16_t *)value) = NETDEV_TYPE_IEEE802154;
            res = sizeof(uint16_t);
            break;
#ifdef MODULE_NETSTATS_L2
        case NETOPT_STATS:
            assert(max_len == sizeof(uintptr_t));
            *((netstats_t **)value) = &g_l2_stats;
            res = sizeof(uintptr_t);
            break;
#endif
        case NETOPT_PROTO:
            assert(max_len == sizeof(gnrc_nettype_t));
            *((gnrc_nettype_t *)value) = _nettype;
            res = sizeof(gnrc_nettype_t);
            break;
        default:
            INFO("NETOPT not handled!! %d\n", opt);
            break;
    }
    return res;
}

#if 0
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
#endif

void *stackline_recvthread(void *args)
{
	msg_t m;
    wf_pkt_t wf_pkt;
	wf_pkt_t *pkt=&wf_pkt;
	int sz;

	(void)args;
	INFO("wf stackline_recvthread started\n");

	while(1) {
		sz = wf_recv_pkt(pkt);	//Blocking call
		if(!sz) continue;
		m.type = WF_EVENT_RX_DONE;
		m.content.ptr = pkt;
		if(!msg_send_int(&m, _wf_netif->pid)) {
			ERROR("msg send failed to internal q, possible lost intr\n");
		}
#if 0
		WAIT_FOR_COND(pkt->len==0,1000);
		if (pkt->len) {
			ERROR("pkt len = %d, was expecting the pkt to be consumed, pkt=%p\n", pkt->len, (void *)pkt);
		}
#endif
	}
	return NULL;
}

static void _netif_msg_handler(gnrc_netif_t *netif, msg_t *msg)
{
    (void)netif;
    switch (msg->type) {
        case WF_EVENT_RX_DONE:
            {
                wf_pkt_t *pkt = msg->content.ptr;
                INFO("wf recvd pkt=%d\n", pkt->len);
                handle_raw_sixlowpan(pkt);
                pkt->len = 0;
                break;
            }
        default:
            ERROR("_netif_msg_handler: Unknown msg->type:%d\n", msg->type);
            break;
    }
}

static int _netif_send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt)
{
    (void)netif;
    assert(netif == _wf_netif);
    return _send(pkt);
}

static gnrc_pktsnip_t *_netif_recv(gnrc_netif_t *netif)
{
    (void)netif;
    /* not supported */
    return NULL;
}

static int _netdev_init(netdev_t *dev)
{
    _wf_netif = dev->context;
    _wf_netif->l2addr_len = WF_L2ADDR_LEN;
	if(wf_get_nodeid() == 0xffff) {
		ERROR("Nodeid not passed white execution. -w <nodeid>\n");
		abort();
	}
    wf_get_longaddr(_wf_netif->l2addr, WF_L2ADDR_LEN);
	if(wf_init()) {
		ERROR("whitefield init failed\n");
		abort();
	}
	INFO("Whitefield Inited. Nodeid=0x%x\n", wf_get_nodeid());
    return 0;
}

static void _netif_init(gnrc_netif_t *netif)
{
	(void)netif;
	gnrc_netif_default_init(netif);
	_netif_thread = thread_get_active();
	INFO("whitefield netif_init called\n");
}

static const gnrc_netif_ops_t _wf_ops = {
    .init = _netif_init,
    .send = _netif_send,
    .recv = _netif_recv,
    .get = gnrc_netif_get_from_netdev,
    .set = gnrc_netif_set_from_netdev,
    .msg_handler = _netif_msg_handler,
};

static const netdev_driver_t _wf_netdev_driver = {
    .send = NULL,
    .recv = NULL,
    .init = _netdev_init,
    .isr  =  NULL,
    .get  = _netdev_get,
    .set  = _netdev_set,
};

static netdev_t _wf_dummy_dev = {
    .driver = &_wf_netdev_driver,
};

void gnrc_whitefield_6lowpan_init(void)
{
    gnrc_netif_create(&_netif, g_stack, sizeof(g_stack), (THREAD_PRIORITY_MAIN - 1),
                      "WF NETAPI", &_wf_dummy_dev, &_wf_ops);
}
