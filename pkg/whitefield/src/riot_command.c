#define	_RIOT_COMMAND_C_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "thread.h"
//#include "net/af.h"
//#include <arpa/inet.h>
#ifdef MODULE_GNRC_NETIF
#include "net/gnrc/netif.h"
#endif
#include "net/fib.h"
#include "net/fib/table.h"
#include "net/gnrc/ipv6.h"

#ifdef MODULE_IPV6_ADDR
#include "net/ipv6/addr.h"
#endif

#define ADD2BUF(...) \
	n += snprintf(buf+n, buflen-n, __VA_ARGS__);

int cmd_config_info(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "todo");
}

int cmd_tcp_stats(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "todo");
}

int cmd_udp_stats(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "todo");
}

int cmd_icmp_stats(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "todo");
}

int cmd_nd6_stats(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "todo");
}

int cmd_node_osname(uint16_t id, char *buf, int buflen)
{
	int n=0;
	(void)id;
	ADD2BUF("{\"os\": \"riot\"}");
	return n;
}

int cmd_rtsize(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "%d", fib_get_num_used_entries(&gnrc_ipv6_fib_table));
}

int cmd_ipv6_stats(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "todo");
}

#define FIB_ADDR_PRINT_LENS1(X)     #X
#define FIB_ADDR_PRINT_LENS2(X)     FIB_ADDR_PRINT_LENS1(X)
#define FIB_ADDR_PRINT_LENS         FIB_ADDR_PRINT_LENS2(FIB_ADDR_PRINT_LEN)

static void get_addr_str(void *entry, char *addr_str, int addr_len)
{
    uint8_t address[UNIVERSAL_ADDRESS_SIZE];
    size_t addr_size = UNIVERSAL_ADDRESS_SIZE;
    uint8_t *ret = universal_address_get_address(entry, address, &addr_size);

	*addr_str=0;
    if (ret == address) {
#ifdef MODULE_IPV6_ADDR
		sprintf(addr_str, "xxxxx %d %d", addr_size, sizeof(ipv6_addr_t));
        if (addr_size == sizeof(ipv6_addr_t)) {
            ipv6_addr_to_str(addr_str, (ipv6_addr_t *) address, addr_len);
            return;
        }
#endif
#if 0
        for (size_t i = 0; i < UNIVERSAL_ADDRESS_SIZE; ++i) {
            if (i <= addr_size) {
                printf("%02x", address[i]);
            }
            else {
                printf("  ");
            }
        }
#ifdef MODULE_IPV6_ADDR
        /* print trailing whitespaces */
        for (size_t i = 0; i < FIB_ADDR_PRINT_LEN - (UNIVERSAL_ADDRESS_SIZE * 2); ++i) {
            printf(" ");
        }
#endif
#endif
    }
}

int get_lifetime_str(uint64_t lifetime, char *buf, int len)
{
	uint64_t now = xtimer_now_usec64();
	if (lifetime != FIB_LIFETIME_NO_EXPIRE) {
		uint64_t tm = lifetime - now;

		/* we must interpret the values as signed */
		if ((int64_t)tm < 0 ) {
			return snprintf(buf, len, "EXPIRED");
		}
		return snprintf(buf, len, "%"PRIu32".%05"PRIu32, (uint32_t)(tm / 1000000),
					(uint32_t)(tm % 1000000));
	}
	return snprintf(buf, len, "NEVER");
}

int get_def_route(char *buf, int buflen)
{
	int pref_len=0;
	fib_table_t *table=&gnrc_ipv6_fib_table;
	mutex_lock(&(table->mtx_access));

	*buf=0;
	if (table->table_type == FIB_TABLE_TYPE_SH) {
        printf("table_sz:%d\n", table->size);
		for (size_t i = 0; i < table->size; ++i) {
            printf("i:%d lifetime:%lld\n", i, table->data.entries[i].lifetime);
			 if (table->data.entries[i].lifetime != 0) {
				pref_len=0;
				if(table->data.entries[i].global_flags & FIB_FLAG_NET_PREFIX_MASK) {
					uint32_t prefix = (table->data.entries[i].global_flags
							& FIB_FLAG_NET_PREFIX_MASK);
					pref_len = (int)(prefix >> FIB_FLAG_NET_PREFIX_SHIFT);
				}
				if(!pref_len) {
                    printf("getting it\n");
					get_addr_str(table->data.entries[i].next_hop, buf, buflen>120?120:buflen);
                    printf("got it\n");
					break;
				}
			}
		}
	}
	mutex_unlock(&(table->mtx_access));
    printf("exiting\n");
	return strlen(buf);
}

int get_route_list(char *buf, int buflen)
{
	int n=0, pref_len=0;
	fib_table_t *table=&gnrc_ipv6_fib_table;
	mutex_lock(&(table->mtx_access));

	if (table->table_type == FIB_TABLE_TYPE_SH) {
		char ltime[64], dst[120], nhop[120];
		//   printf("%-" FIB_ADDR_PRINT_LENS "s %-17s %-" FIB_ADDR_PRINT_LENS "s %-10s %-16s"
		//          " Interface\n" , "Destination", "Flags", "Next Hop", "Flags", "Expires");

		for (size_t i = 0; i < table->size; ++i) {
			if (table->data.entries[i].lifetime != 0) {
				get_addr_str(table->data.entries[i].global, dst, sizeof(dst));
				pref_len=0;
				if(table->data.entries[i].global_flags & FIB_FLAG_NET_PREFIX_MASK) {
					uint32_t prefix = (table->data.entries[i].global_flags
							& FIB_FLAG_NET_PREFIX_MASK);
					pref_len = (int)(prefix >> FIB_FLAG_NET_PREFIX_SHIFT);
				}
				get_addr_str(table->data.entries[i].next_hop, nhop, sizeof(nhop));
				//printf(" 0x%08"PRIx32" ", table->data.entries[i].next_hop_flags);
				get_lifetime_str(table->data.entries[i].lifetime, ltime, sizeof(ltime));
				if(n) {
					ADD2BUF(",");
				}
				ADD2BUF("{ \"prefix\": \"%s\", \"pref_len\": \"%d\", \"next_hop\": \"%s\", \"lifetime\":\"%s\" }\n", 
						dst, pref_len, nhop, ltime);
				//printf("%d\n", (int)table->data.entries[i].iface_id);
				if(n > buflen-100) {
					ADD2BUF("[TRUNC]");
					break;
				}   
			}
		}
	}
#if 0
	else if (table->table_type == FIB_TABLE_TYPE_SR) {
		printf("%-" FIB_ADDR_PRINT_LENS "s %-" FIB_ADDR_PRINT_LENS "s %-6s %-16s Interface\n"
				, "SR Destination", "SR First Hop", "SR Flags", "Expires");
		for (size_t i = 0; i < table->size; ++i) {
			if (table->data.source_routes->headers[i].sr_lifetime != 0) {
				fib_print_address(table->data.source_routes->headers[i].sr_dest->address);
				fib_print_address(table->data.source_routes->headers[i].sr_path->address);
				printf(" 0x%04"PRIx32" ", table->data.source_routes->headers[i].sr_flags);

				if (table->data.source_routes->headers[i].sr_lifetime != FIB_LIFETIME_NO_EXPIRE) {

					uint64_t tm = table->data.source_routes->headers[i].sr_lifetime - now;

					/* we must interpret the values as signed */
					if ((int64_t)tm < 0 ) {
						printf("%-16s ", "EXPIRED");
					}
					else {
						printf("%"PRIu32".%05"PRIu32, (uint32_t)(tm / 1000000),
								(uint32_t)(tm % 1000000));
					}
				}
				else {
					printf("%-16s ", "NEVER");
				}

				printf("%d\n", (int)table->data.source_routes->headers[i].sr_iface_id);
			}
		}
	}
#endif
	mutex_unlock(&(table->mtx_access));
	return n;
}

int cmd_route_table(uint16_t id, char *buf, int buflen)
{
	int n=0;
	(void)id;
	ADD2BUF("{ \"route_table\": {\n");
	ADD2BUF("\t\"routes\": [\n");
	n += get_route_list(buf+n, buflen-n);
	ADD2BUF("]\n}}");
	return n;
}

int cmd_rpl_stats(uint16_t id, char *buf, int buflen)
{
	(void)id;
	return snprintf(buf, buflen, "todo");
}

int cmd_def_route(uint16_t id, char *buf, int buflen)
{
	(void)id;
    printf("handle_cmd: cmd_def_route id=%d\n", id);
	return get_def_route(buf, buflen);
}

