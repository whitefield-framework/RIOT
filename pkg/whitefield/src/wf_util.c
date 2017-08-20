#define	_WF_UTIL_C_

#include <string.h>
#include "whitefield.h"
#include "commline.h"

#include "net/ieee802154.h"

extern uint16_t wf_nodeid;	//originally defined in cpu/native/startup.c
uint16_t wf_get_nodeid(void)
{
	return wf_nodeid;
}

int wf_get_longaddr(uint8_t *value, unsigned int val_len)
{
	uint16_t nworderid=htons(wf_nodeid);
	assert(val_len >= IEEE802154_LONG_ADDRESS_LEN);
	memset(value, 0, val_len);
	memcpy(value+6, &nworderid, sizeof(nworderid));
	return 0;
}

int wf_init(void)
{
	if(cl_init(CL_ATTACHQ)!= CL_SUCCESS) {
		ERROR("Failure attaching to commline\n");
		return -1;
	}
	return 0;
}

