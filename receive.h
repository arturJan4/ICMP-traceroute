#ifndef TRACEROUTE_RECEIVE_H
#define TRACEROUTE_RECEIVE_H
#include <stdint.h>

typedef struct {
  int64_t ms;  // time in miliseconds
  int reached_goal;
  char ip_addresses[64];  // ip addresses string
} line_struct;

line_struct* receive_packets(int sockfd, uint16_t seq_arr[], uint16_t pid,
                             char* goal_address);

#endif  // TRACEROUTE_RECEIVE_H
