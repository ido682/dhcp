#ifndef __DHCP_H__
#define __DHCP_H__

#include <stddef.h> /* size_t */

#define IP_V (4)
typedef struct dhcp dhcp_t;
typedef unsigned char byte_t;
typedef byte_t ip_adrs_t[IP_V];

/************************************************************************/

dhcp_t *DHCPCreate (ip_adrs_t net_ip, unsigned int cidr_net_mask);
/*                   
net_ip - a valid ip address which represents only the netwrok part.
cidr_net_mask - a number (between 1 and 32) representing the number 
of bits resereved for network address.
*/

void DHCPDestroy(dhcp_t *dhcp);

int DHCPAllocIP(dhcp_t *dhcp, ip_adrs_t requested_ip, ip_adrs_t returned_ip);
/*                   
requested_ip - the ip requested by user (optional, use 0 for default).
returned_ip - the actual ip that was allocated by the server (out param).

Returnes 0 on success, 1 on failure.
*/

void DHCPFreeIp(dhcp_t *dhcp, ip_adrs_t ip_adrs_to_free);
/*       	 
If a reserved ip is passed, the function frees nothing.
*/

size_t DHCPCountFree(const dhcp_t *dhcp);


#endif /* __DHCP_H__ */

