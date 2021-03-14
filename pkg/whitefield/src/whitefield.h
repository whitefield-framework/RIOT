#ifndef	_WHITEFIELD_H_
#define	_WHITEFIELD_H_

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

/*
	Configuration Options
*/
#define	WF_MAX_PKT_SZ	127
#ifndef WF_MAX_FRAG_SZ
#define	WF_MAX_FRAG_SZ	90
#endif
#define	WF_L2ADDR_LEN	8

#ifndef	ENABLE_DEBUG
#define ENABLE_DEBUG    (1)
#endif
#include "debug.h"

#define PRN(STR, ...)                                 \
    {                                                 \
        struct timeval tv;                            \
        gettimeofday(&tv, NULL);                      \
        printf("%s %5ld:%-4ld[%s:%d] ", STR,          \
               tv.tv_sec % 100000, tv.tv_usec / 1000, \
               __func__, __LINE__);                   \
        printf(__VA_ARGS__);                          \
		fflush(NULL);								  \
    }

#define	ERROR(...)	PRN("ERROR", __VA_ARGS__)
#define	INFO(...)	PRN("INFO ", __VA_ARGS__)
#define WARN(...)   PRN("WARN " __VA_ARGS__)

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

