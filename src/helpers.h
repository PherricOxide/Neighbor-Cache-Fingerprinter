#ifndef HELPERS_H_
#define HELPERS_H_

#include <dumbnet.h>

// Some helpers for address packing

void addr_pack_eth(addr* addr, uint8_t* eth);

void addr_pack_ip(addr* addr, uint8_t* ip);

#endif
