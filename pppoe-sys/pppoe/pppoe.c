#include "pppoe.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include <linux/types.h>
#include <linux/ppp_defs.h>
#include <linux/if_pppox.h>

static int control_socket = 0;


static int get_interface_index_from_name(struct PppoeConnectionData const *const data) {
	assert(NULL != data);

	struct ifreq ifr;

	strncpy(ifr.ifr_name, data->interface_name, sizeof ifr.ifr_name);

	if (ioctl(control_socket, SIOCGIFINDEX, &ifr) < 0) return -1;

	return ifr.ifr_ifindex;
}


int control_socket_init(void) {
	if (control_socket == 0) {
		control_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	}
	return control_socket;
}


void control_socket_close(void) {
	if (control_socket != 0) {
		close(control_socket);
		control_socket = 0;
	}
}


int lookup_hardware_address(struct PppoeConnectionData *const data) {
	assert(NULL != data);

	struct ifreq ifr;

	strncpy(ifr.ifr_name, data->interface_name, sizeof ifr.ifr_name);

	if (ioctl(control_socket, SIOCGIFHWADDR, &ifr) < 0) return -1;

	memcpy(data->mac_address, ifr.ifr_hwaddr.sa_data, sizeof data->mac_address);

	return 0;
}


int pppoe_connection_data_set_name(struct PppoeConnectionData *data, char const * const interface_name) {
	assert(NULL != data);
	assert(NULL != interface_name);
	assert(strlen(interface_name) > 0);
	assert(strlen(interface_name) <= IFNAMSIZ);

	strncpy(data->interface_name, interface_name, IFNAMSIZ);

	return lookup_hardware_address(data);
}


int pppoe_connection_data_init(struct PppoeConnectionData *data, char const *const interface_name) {
	assert(NULL != data);

	if ((data->pppoe_socket = pppoe_create_socket()) < 0) {
		return -1;
	}

	if (NULL != interface_name) {
		assert(strlen(interface_name) > 0);
		assert(strlen(interface_name) <= IFNAMSIZ);
		if (pppoe_connection_data_set_name(data, interface_name) < 0) {
			goto PPPOE_CONNECTION_DATA_INIT_CLEANUP;
		};
	}

	if ((pppoe_raw_socket_create(data)) < 0) goto PPPOE_CONNECTION_DATA_INIT_CLEANUP;
	if ((pppoe_raw_socket_bind(data)) < 0) goto PPPOE_CONNECTION_DATA_INIT_CLEANUP;

	return 0;

PPPOE_CONNECTION_DATA_INIT_CLEANUP:
	pppoe_connection_data_clear(data);
	return -1;
}


void pppoe_connection_data_clear(struct PppoeConnectionData *const data) {
	assert(NULL != data);

	if (data->pppoe_socket != 0) close(data->pppoe_socket);
	if (data->raw_socket != 0) close(data->raw_socket);

	memset(data, '\0', sizeof *data);
}


int pppoe_create_socket(void) {
	return socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
}


int pppoe_connect(struct PppoeConnectionData const *const data, uint16_t pppoe_session_id) {
	assert(NULL != data);

	struct sockaddr_pppox sp;

	sp.sa_family = AF_PPPOX;
	sp.sa_protocol = PX_PROTO_OE;
	sp.sa_addr.pppoe.sid = pppoe_session_id;

	memcpy(sp.sa_addr.pppoe.dev, data->interface_name, sizeof sp.sa_addr.pppoe.dev);
	memcpy(sp.sa_addr.pppoe.remote, data->mac_address, sizeof sp.sa_addr.pppoe.remote);

	return connect(data->pppoe_socket, (struct sockaddr *) &sp, sizeof sp);
}


int pppoe_raw_socket_create(struct PppoeConnectionData *const data) {
	assert(NULL != data);
	int optval = 1;

	if ((data->raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_PPPOE_DISCOVERY))) < 0)
		return -1;

	if (setsockopt(data->raw_socket, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
		goto OPEN_INTERFACE_CLOSE_SOCKET;

	return 0;

OPEN_INTERFACE_CLOSE_SOCKET:
	close(data->raw_socket);
	data->raw_socket = 0;
	return -1;
}


int pppoe_raw_socket_bind(struct PppoeConnectionData const *const data) {
	assert(NULL != data);

	struct sockaddr_ll sa;

	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_PPPOE_DISCOVERY);

	if ((sa.sll_ifindex = get_interface_index_from_name(data)) < 0)
		return -1;

	if (bind(data->raw_socket, (struct sockaddr *) &sa, sizeof sa) < 0)
		return -1;

	return 0;
}
