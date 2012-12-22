// Some helpers for address packing

void addr_pack_eth(addr* addr, uint8_t* eth)
{
	addr_pack(addr, ADDR_TYPE_ETH, ETH_ADDR_BITS, eth, ETH_ADDR_LEN);
}

void addr_pack_ip(addr* addr, uint8_t* ip)
{
	addr_pack(addr, ADDR_TYPE_IP, IP_ADDR_BITS, ip, IP_ADDR_LEN);
}
