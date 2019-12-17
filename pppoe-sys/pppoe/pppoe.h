#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>


#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864


struct PppoeConnectionData {
	int pppoe_socket;
	int raw_socket;
	char interface_name[IFNAMSIZ];
	unsigned char mac_address[ETH_ALEN];
};

int pppoe_create_socket(void);
int pppoe_connect(struct PppoeConnectionData const *const data, uint16_t session_id); 

int pppoe_raw_socket_create(struct PppoeConnectionData *const data);
int pppoe_raw_socket_bind(struct PppoeConnectionData const *const data);
int pppoe_raw_socket_send();

int pppoe_connection_data_init(struct PppoeConnectionData *, char const *const);
int pppoe_connection_data_set_name(struct PppoeConnectionData *, char const *const);
void pppoe_connection_data_clear(struct PppoeConnectionData *const);

int ppp_channel_from_fd(int fd);
int lookup_hardware_address(struct PppoeConnectionData *const data);
