#ifndef	_WHITEFIELD_H_
#define	_WHITEFIELD_H_

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

/*
	Configuration Options
*/
#define	WF_MAX_PKT_SZ	127

#ifndef	ENABLE_DEBUG
#define ENABLE_DEBUG    (1)
#endif
#include "debug.h"

#define	ERROR(...)	fprintf(stderr,__VA_ARGS__)
#define	INFO(...)	DEBUG(__VA_ARGS__)

int wf_init(void);
uint16_t wf_get_nodeid(void);
int wf_get_longaddr(uint8_t *value, unsigned int val_len);
int wf_send_pkt(const uint8_t *dst, const uint8_t *buf, const unsigned len);

#endif	//	_WHITEFIELD_H_
