#ifndef TRACEROUTE_SEND_H
#define TRACEROUTE_SEND_H
#include <stdlib.h>

// send packet to addr with given TTL, and <seqnum, pid> for identification.
void send_packet(int sockfd, char *addr, int ttl, int seqnum, u_int16_t pid);

#endif  // TRACEROUTE_SEND_H
