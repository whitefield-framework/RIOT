#ifndef	_WHITEFIELD_H_
#define	_WHITEFIELD_H_

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

/*
	Configuration Options
*/
#define	WF_MAX_PKT_SZ	127
#define	WF_L2ADDR_LEN	8

#ifndef	ENABLE_DEBUG
#define ENABLE_DEBUG    (1)
#endif
#include "debug.h"

#define	ERROR(...)	fprintf(stderr,__VA_ARGS__)
#define	INFO(...)	DEBUG(__VA_ARGS__)

typedef struct _wf_pkt_ {
	uint8_t src[WF_L2ADDR_LEN];
	uint8_t dst[WF_L2ADDR_LEN];
	uint8_t buf[WF_MAX_PKT_SZ];
	uint16_t len;
	int8_t rssi;
	uint8_t lqi;
}wf_pkt_t;

int wf_init(void);
uint16_t wf_get_nodeid(void);
int wf_get_longaddr(uint8_t *value, unsigned int val_len);
int wf_send_pkt(const uint8_t *dst, const uint8_t *buf, const unsigned len);
int wf_recv_pkt(wf_pkt_t *pkt);

#endif	//	_WHITEFIELD_H_

