#ifndef ARP_ATTACK_H
#define ARP_ATTACK_H

#include <stdint.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "parse.h"

void getAttackerMAC(const char * dev, uint8_t * mac);
void make_arp_packet(uint32_t senderIP, uint8_t * sender_mac, ARP_Packet * packet);
void start_attack(u_char * arp_pkt, char * dev);

#endif // ARP_ATTACK_H
