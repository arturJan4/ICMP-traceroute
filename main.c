// Artur Jankowski, 317928
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "receive.h"
#include "send.h"

/* Uncomment this line for debugging output */
//#define DEBUG
#ifdef DEBUG
#define debug(fmt, ...) printf("%s: " fmt "\n", __func__, __VA_ARGS__)
#define msg(...) printf(__VA_ARGS__)
#else
#define debug(fmt, ...)
#define msg(...)
#endif

void traceroute(char **argv) {
  // socket file descriptor
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    fprintf(stderr, "socket error: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  uint16_t pid = (uint16_t)getpid();
  debug("pid: %d", pid);

  printf("traceroute to %s (%s), 30 hops max\n", argv[1], argv[1]);

  for (int ttl = 1; ttl <= 30; ++ttl) {
    // idea: seqnum // 3 == ttl
    uint16_t seq_arr[3] = {(uint16_t)(3 * ttl), (uint16_t)(3 * ttl + 1),
                           (uint16_t)(3 * ttl + 2)};
    // send 3 ICMP echo request packets
    send_packet(sockfd, argv[1], ttl, seq_arr[0], pid);
    send_packet(sockfd, argv[1], ttl, seq_arr[1], pid);
    send_packet(sockfd, argv[1], ttl, seq_arr[2], pid);
    msg("\n========================\n");
    line_struct *line = receive_packets(sockfd, seq_arr, pid, argv[1]);

    // print using information from line_struct
    printf("%d. ", ttl);

    // no reply from router
    if (strcmp(line->ip_addresses, "*") == 0) {
      printf("*\n");
      free(line);
      continue;
    }

    // print 1 or more unique ip addresses
    printf("%s ", line->ip_addresses);

    // time limit (1s) was exceeded
    if (line->ms == -1) {
      printf("???");
    } else {  // print average response time
      printf("%ldms", line->ms);
    }

    printf("\n");

    if (line->reached_goal) {
      debug("%s", "dest reached");
      free(line);
      break;
    }

    free(line);
  }

  int result = close(sockfd);
  if (result != 0) {
    fprintf(stderr, "socket closing error: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s [ip addr] (needs root)\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (getuid()) {
    printf("You must be root (use: sudo %s)!\n", argv[0]);
    return EXIT_FAILURE;
  }

  traceroute(argv);

  return EXIT_SUCCESS;
}
