#include <stdlib.h> /* malooc */
#include <assert.h> /* assert */
#include <string.h> /* memcpy */
#include <math.h> /* pow */

#include "dhcp.h"

#define MIN_CIDR 16
#define MAX_CIDR 24
#define BITS_IN_BYTE 8
#define TOTAL_BITS (BITS_IN_BYTE * IP_V)
#define MAX_VARIABLE_BITS (TOTAL_BITS - MIN_CIDR)
#define MIN_VARIABLE_BITS (TOTAL_BITS - MAX_CIDR)
#define BADCOFFEE (void *)0xBADC0FFEE /* invalid address */

typedef struct node node_t;
typedef struct info info_t;

typedef enum CHILD_ENUMS
{
	LEFT = 0, 
	RIGHT = 1, 
	CHILD_ENUM_COUNT = 2
} child_t;

typedef enum STATUS_ENUMS
{
	SUCCESS,
	FAILURE,
	STATUS_ENUMS_COUNT
} status_t;

struct node
{
	node_t *children[CHILD_ENUM_COUNT];
	/* is_full field improves performance, by reducing the need to check
	thousands of occupied ip addresses under a certain node */
	int is_full;
};

struct dhcp
{
	int num_of_constant_bits;
	ip_adrs_t network_ip_mask;
	node_t *stub;
};

/* use in struct is for enabling future features */
struct info
{
	child_t *arr_ip;
};

static byte_t constant1[IP_V] = {0, 0, 0, 0};
static byte_t constant2[IP_V] = {255, 255, 255, 255};
static byte_t constant3[IP_V] = {255, 255, 255, 254};

static void DestroyRecursive(node_t *root_node);
static size_t CountRecursive(const node_t *root_node);
static status_t PaveIPPath(node_t *node, int bit_idx, info_t alloc_info);
static void IPToArray(dhcp_t *dhcp, ip_adrs_t ip_adrs,
					  child_t arr_ip[TOTAL_BITS]);
static node_t *CreateRegularNode();
static node_t *CreateFinalNode();
static void DestroyRecursive(node_t *root_node);
static size_t CountRecursive(const node_t *root_node);
static int IsLeaf(const node_t *node);
static node_t *CreateChildren(int bit_idx, info_t alloc_info);
static void UpdateIsFull(node_t *node);
static void ArrayToIP(child_t arr_ip[], ip_adrs_t ip_adrs);
static status_t FreeRecursive(node_t *node, int bit_idx, info_t free_info);
static int IsFinalNode(const node_t *node);


/*******************************************************************/

dhcp_t *DHCPCreate(ip_adrs_t net_ip, unsigned int num_of_constant_bits)
{
	dhcp_t *dhcp = NULL;
	node_t *stub = NULL;
	int status = 0;
	byte_t returned_ip[IP_V] = {0, 0, 0, 0};
	
	assert(net_ip != NULL);
	assert(*net_ip != 0);
	assert(num_of_constant_bits >= MIN_CIDR);
	assert(num_of_constant_bits <= MAX_CIDR);

	dhcp = malloc(sizeof(dhcp_t));
	if (NULL == dhcp)
	{
		return (NULL);
	}

	stub = CreateRegularNode();
	if (NULL == stub)
	{
		free(dhcp);
		dhcp = NULL;
		return (NULL);
	}

	dhcp->num_of_constant_bits = num_of_constant_bits;
	dhcp->stub = stub;

	/* net_ip has to be saved by value */
	memcpy(dhcp->network_ip_mask, net_ip, IP_V);

	status = DHCPAllocIP(dhcp, constant1, returned_ip);
	if (status != 0)
	{
		/* stub is freed in DHCPDestroy */
		DHCPDestroy(dhcp);
		dhcp = NULL;

		return (NULL);
	}

	status = DHCPAllocIP(dhcp, constant2, returned_ip);
	if (status != 0)
	{
		/* stub is freed in DHCPDestroy */
		DHCPDestroy(dhcp);
		dhcp = NULL;

		return (NULL);
	}

	status = DHCPAllocIP(dhcp, constant3, returned_ip);
	if (status != 0)
	{
		/* stub is freed in DHCPDestroy */
		DHCPDestroy(dhcp);
		dhcp = NULL;

		return (NULL);
	}

	return (dhcp);
}

/***********/
void DHCPDestroy(dhcp_t *dhcp)
{
	assert(dhcp != NULL);

	DestroyRecursive(dhcp->stub);

	free(dhcp);
	dhcp = NULL;
}

/***********/
static void DestroyRecursive(node_t *root_node)
{
	if ((BADCOFFEE == root_node) || (NULL == root_node))
	{
		return;
	}

	DestroyRecursive(root_node->children[LEFT]);
	DestroyRecursive(root_node->children[RIGHT]);

	free(root_node);
	root_node = NULL;
}

/***********/
size_t DHCPCountFree(const dhcp_t *dhcp)
{
	size_t num_of_optional_ips = 0;
	size_t num_of_ips = 0;
	size_t num_of_variable_bits = 0;

	assert(dhcp != NULL);

	num_of_variable_bits = TOTAL_BITS - dhcp->num_of_constant_bits;
	num_of_optional_ips = pow(2, num_of_variable_bits);
	num_of_ips = CountRecursive(dhcp->stub);

	return (num_of_optional_ips - num_of_ips);
}

/***********/
/* the number of ip addresses in use is the number of final nodes exist */
static size_t CountRecursive(const node_t *root_node)
{
	size_t nodes_ctr = 0;

	if (NULL == root_node)
	{
		return (0);
	}
	
	if (IsFinalNode(root_node))
	{
		return (1);
	}

	nodes_ctr += CountRecursive(root_node->children[LEFT]);
	nodes_ctr += CountRecursive(root_node->children[RIGHT]);

	return (nodes_ctr);
}

/***********/
static int IsFinalNode(const node_t *node)
{
	assert(node != NULL);

	return (BADCOFFEE == node->children[LEFT]);
}

/***********/
static int IsLeaf(const node_t *node)
{
	assert(node != NULL);

	return ((NULL == node->children[LEFT]) &&
			(NULL == node->children[RIGHT]));
}

/***********/
int DHCPAllocIP(dhcp_t *dhcp, ip_adrs_t requested_ip, ip_adrs_t returned_ip)
{
	child_t arr_ip[TOTAL_BITS] = {LEFT}; /* 0 */
	info_t alloc_info = {0};
	status_t status = FAILURE;
	int bit_idx = 0;

	assert(dhcp != NULL);
	assert(requested_ip != NULL);

	/* represents requested_ip and network_ip_mask as arrays of child_t
	(0 or 1,aka LEFT or RIGHT), and copies the network_ip_mask
	to the new ip address */
	IPToArray(dhcp, requested_ip, arr_ip);

	alloc_info.arr_ip = arr_ip;
	/* sets the first index thus the constant bits won't be overwritten */
	bit_idx = dhcp->num_of_constant_bits;

	/* moves forward in the tree according to the ip requested by the user
	(if possible), until reaches a NULL, and than creates new nodes */
	status = PaveIPPath(dhcp->stub, bit_idx, alloc_info);

	ArrayToIP(arr_ip, returned_ip);

	return (status);
}

/***********/
/* the functions has two phases:
1. goes by the required ip address with the existing nodes.
2. when propriate nodes no more exists -
creates them (using CreateChildren()). */
static status_t PaveIPPath(node_t *node, int bit_idx, info_t alloc_info)
{
	node_t *child = NULL;
	child_t i = 0;
	child_t current_bit = LEFT;
	status_t status = FAILURE;

	current_bit = alloc_info.arr_ip[bit_idx];
	child = node->children[current_bit];

	if (LEFT == current_bit)
	{
		/* left child is NULL - create new nodes */
		if (NULL == child)
		{
			node->children[LEFT] = CreateChildren(bit_idx + 1, alloc_info);
			if (NULL == node->children[LEFT])
			{
				/* new allocated nodes are freed inside CreateChildren */
				return (FAILURE);
			}
			UpdateIsFull(node);
			return (SUCCESS);
		}
		/* left child isn't NULL and isn't full - trying to pave a path
		in that direction (recursively) */
		else if (!child->is_full)
		{
			status = PaveIPPath(child, bit_idx + 1, alloc_info);
			/* a path was paved via left child - success */
			if (SUCCESS == status)
			{
				UpdateIsFull(node);
				return (SUCCESS);
			}
		}
	
		/* couldn't pave a path via left child, trying via right child.
		The arr_ip is updated and the recursive function is invoked
		with the same node (the arr_ip will direct to right child) */
		alloc_info.arr_ip[bit_idx] = RIGHT;
		for (i = 1; (bit_idx + i) < TOTAL_BITS; ++i)
		{
			alloc_info.arr_ip[bit_idx + i] = 0;
		}

		status = PaveIPPath(node, bit_idx, alloc_info);
		if (SUCCESS == status)
		{
			UpdateIsFull(node);
			return (SUCCESS);
		}	
	}

	/* (RIGHT == current_bit) */
	else 
	{
		/* Right child is NULL - create new nodes */
		if (NULL == child)
		{
			node->children[RIGHT] = CreateChildren(bit_idx + 1, alloc_info);
			if (NULL == node->children[RIGHT])
			{
				return (FAILURE);
			}
			UpdateIsFull(node);
			return (SUCCESS);
		}
		/* Right child isn't NULL and isn't full - trying to pave a path
		in that direction (recursively) */
		else if (!child->is_full)
		{
			status = PaveIPPath(child, bit_idx + 1, alloc_info);
			if (SUCCESS == status)
			{
				UpdateIsFull(node);
				return (status);
			}
		}
	}

	/* None of the options went well - failure (of this specific
	call of the function) */
	return (FAILURE);
}

/***********/
static node_t *CreateChildren(int bit_idx, info_t alloc_info)
{
	node_t *node = NULL;
	node_t *created_node = NULL;

	/* the next node will represent the last bit in the ip address,
	so it should be a final node */
	if (bit_idx == TOTAL_BITS)
	{
		node = CreateFinalNode();
		if (NULL == node)
		{
			return (NULL);
		}
	}
	/* the next node won't represent the last bit in the ip address,
	so it should be a reaular node, and keep on creating other nodes */
	else
	{
		node = CreateRegularNode();
		if (NULL == node)
		{
			return (NULL);
		}

		created_node = CreateChildren(bit_idx + 1, alloc_info);
		if (NULL == created_node)
		{
			free(node);
			node = NULL;
			return (NULL);
		}
		node->children[alloc_info.arr_ip[bit_idx]] = created_node;

		UpdateIsFull(node);
	}

	return (node);
}

/***********/
static void IPToArray(dhcp_t *dhcp, ip_adrs_t ip_adrs,
					  child_t arr_ip[TOTAL_BITS])
{
	child_t arr_net_ip[TOTAL_BITS] = {LEFT};
	int arr_idx = 0;
	int bit_idx = 0;
	int byte_idx = 0;

	for (byte_idx = 0; byte_idx < IP_V; ++byte_idx)
	{
		for (bit_idx = BITS_IN_BYTE - 1; bit_idx >= 0; --bit_idx)
		{
			arr_ip[arr_idx] = (ip_adrs[byte_idx] >> bit_idx) & 1;
			++arr_idx;
		}
	}

	arr_idx = 0;

	for (byte_idx = 0; byte_idx < IP_V; ++byte_idx)
	{
		for (bit_idx = BITS_IN_BYTE - 1; bit_idx >= 0; --bit_idx)
		{
			arr_net_ip[arr_idx] =
				(dhcp->network_ip_mask[byte_idx] >> bit_idx) & 1;
			++arr_idx;
		}
	}

	memcpy(arr_ip, arr_net_ip, dhcp->num_of_constant_bits * sizeof(child_t));
}

/***********/
static void ArrayToIP(child_t arr_ip[], ip_adrs_t ip_adrs)
{
	int arr_idx = 0;
	int bit_idx = 0;
	int byte_idx = 0;

	for (byte_idx = 0; byte_idx < IP_V; ++byte_idx)
	{
		for (bit_idx = BITS_IN_BYTE - 1; bit_idx >= 0; --bit_idx)
		{
			ip_adrs[byte_idx] <<= 1;
			ip_adrs[byte_idx] |= (arr_ip[arr_idx++]);
		}
	}
}

/***********/
/* a "regular node" is a node which does NOT represent
the end of the ip address */
static node_t *CreateRegularNode()
{
	node_t *node = malloc(sizeof(node_t));
	if (NULL == node)
	{
		return (NULL);
	}

	node->children[LEFT] = NULL;
	node->children[RIGHT] = NULL;
	node->is_full = 0;

	return (node);
}

/***********/
/* a "final node" is a node which represents the end of the ip address */
static node_t *CreateFinalNode()
{
	node_t *node = malloc(sizeof(node_t));
	if (NULL == node)
	{
		return (NULL);
	}

	node->children[LEFT] = BADCOFFEE;
	node->children[RIGHT] = BADCOFFEE;
	node->is_full = 1;

	return (node);
}

/***********/
static void UpdateIsFull(node_t *node)
{
	node->is_full = ((node->children[LEFT] != NULL) &&
					 (node->children[LEFT]->is_full) &&
					 (node->children[RIGHT] != NULL) &&
					 (node->children[RIGHT]->is_full));
}

/***********/
void DHCPFreeIp(dhcp_t *dhcp, ip_adrs_t ip_adrs_to_free)
{
	child_t arr_ip[TOTAL_BITS] = {LEFT}; /* 0 */
	child_t arr_constant_ip_1[TOTAL_BITS] = {LEFT};
	child_t arr_constant_ip_2[TOTAL_BITS] = {LEFT};
	child_t arr_constant_ip_3[TOTAL_BITS] = {LEFT};
	info_t free_info = {0};
	int bit_idx = 0;
	int bits_to_compare = 0;

	assert(dhcp != NULL);
	assert(ip_adrs_to_free != NULL);

	IPToArray(dhcp, ip_adrs_to_free, arr_ip);

	/* Makes sure the constant ips won't be freed */
	IPToArray(dhcp, constant3, arr_constant_ip_3);
	IPToArray(dhcp, constant2, arr_constant_ip_2);
	IPToArray(dhcp, constant1, arr_constant_ip_1);
	
	bits_to_compare = TOTAL_BITS * sizeof(child_t);

	if ( (0 == memcmp(arr_constant_ip_1, arr_ip, bits_to_compare)) ||
		 (0 == memcmp(arr_constant_ip_2, arr_ip, bits_to_compare)) ||
		 (0 == memcmp(arr_constant_ip_3, arr_ip, bits_to_compare)) )
	{
		return;
	}

	free_info.arr_ip = arr_ip;

	/* sets the first index thus the constant bits will be ignored */
	bit_idx = dhcp->num_of_constant_bits - 1;

	FreeRecursive(dhcp->stub, bit_idx, free_info);
}

/***********/
static status_t FreeRecursive(node_t *node, int bit_idx, info_t free_info)
{
	status_t status = FAILURE;

	/* ip address doesn't exist */
	if (NULL == node)
	{
		return (FAILURE);
	}

	/* ip address is found */
	if (bit_idx == TOTAL_BITS - 1)
	{
		return (SUCCESS);
	}

	status = FreeRecursive(node->children[free_info.arr_ip[bit_idx + 1]],
						   bit_idx + 1, free_info);

	if (SUCCESS == status)
	{
		/* updated only if an ip was removed */
		node->is_full = 0;
		
		/* child node is freed only if didn't have a child on the other side */
		if ((IsLeaf(node->children[(free_info.arr_ip[bit_idx + 1])])) ||
		   IsFinalNode(node->children[(free_info.arr_ip[bit_idx + 1])]))
		{
			free(node->children[free_info.arr_ip[bit_idx + 1]]);
			node->children[free_info.arr_ip[bit_idx + 1]] = NULL;
		}
	}

	return (status);
}

