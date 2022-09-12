// Artur Jankowski, 317928

#include "receive.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Uncomment this line for debugging output */
//#define DEBUG
#ifdef DEBUG
#define debug(fmt, ...) printf("%s: " fmt "\n", __func__, __VA_ARGS__)
#define msg(...) printf(__VA_ARGS__)
#else
#define debug(fmt, ...)
#define msg(...)
#endif

static struct icmp *extract_te_header(struct icmp *icmp_header) {
  debug("%s", "type time exceeded");

  struct ip *temp_header =
      (struct ip *)((char *)icmp_header + (ssize_t)sizeof(struct icmphdr));
  ssize_t temp_header_len = (uint)4 * temp_header->ip_hl;

  // extract shifted header
  struct icmp *shift_header =
      (struct icmp *)((char *)temp_header + temp_header_len);
  return shift_header;
}

// checks if packet is one of those we are waiting for
static int is_correct_packet(struct icmp *icmp_header, uint16_t pid,
                             const uint16_t seq_arr[]) {
  if (!icmp_header) {
    fprintf(stderr, "null icmp header during is_correct_packet\n");
    exit(EXIT_FAILURE);
  }

  // check type (0 - echo, 11 - time exceeded)
  if (((icmp_header->icmp_type == (uint8_t)0) ||
       (icmp_header->icmp_type == (uint8_t)11)) == 0) {
    debug("%s %d", "wrong type", icmp_header->icmp_type);
    return 0;
  }

  if (icmp_header->icmp_type == 0) {
    debug("%s", "type echo");
  }

  if (icmp_header->icmp_type == 11) {
    debug("%s", "type: time exceeded");

    icmp_header = extract_te_header(icmp_header);
  }

  // received PID as ID
  uint16_t pid_rec = ntohs(icmp_header->icmp_hun.ih_idseq.icd_id);

  // received PID must match traceroute's PID
  if (pid != pid_rec) {
    debug("%d %s %d", pid, "pid doesn't match", pid_rec);
    return 0;
  }

  uint16_t seq = ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq);
  // sequence number must match
  // we send 3 ICMP requests at once so we must check all three here
  if ((seq == seq_arr[0] || seq == seq_arr[1] || seq == seq_arr[2]) == 0) {
    debug("%s", "seq doesn't match");
    return 0;
  }

  debug("%s", "packet is correct");

  return 1;
}

static line_struct *build_output(char ip_addresses[3][20],
                                 const uint64_t response_times[3], int timeout,
                                 char *goal_address) {
    line_struct *retval = malloc(sizeof(line_struct));

  if (timeout == 0) {
      uint64_t sum = 0;
      for (int i = 0; i < 3; ++i) {
      sum += response_times[i];
    }
      retval->ms = sum / 3;
  } else {
      retval->ms = -1;
  }

  char ip_addresses_str[64] = "";
  int added = 0;         // added valid address to output str
  int reached_goal = 0;  // reached destination ip address
  for (int i = 0; i < 3 - timeout; ++i) {
    debug("ip addr: %s", ip_addresses[i]);
    if (strcmp(ip_addresses[i], "") == 0) continue;

    if (strcmp(ip_addresses[i], goal_address) == 0) {
      strcpy(ip_addresses_str, ip_addresses[i]);
      added = 1;
      reached_goal = 1;
      break;
    }

    // check if matches any of previous
    int matches = 0;
    for (int j = 0; j < i; ++j) {
      if (strcmp(ip_addresses[j], ip_addresses[i]) == 0) matches = 1;
    }
    if (!matches) {
      if (added > 0) {
        strcat(ip_addresses_str, " ");
      }
      strcat(ip_addresses_str, ip_addresses[i]);
      added++;
    }
  }

  if (added == 0)
      strcat(ip_addresses_str, "*");

  retval->reached_goal = reached_goal;
  strcpy(retval->ip_addresses, ip_addresses_str);

  return retval;
}

line_struct *receive_packets(int sockfd, uint16_t seq_arr[], uint16_t pid,
                             char *goal_address) {
  fd_set descriptors;
  FD_ZERO(&descriptors);
  FD_SET(sockfd, &descriptors);

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;  // usec -> microseconds

  int received_packets = 0;
  char ip_addresses[3][20] = {"", "", ""};
  uint64_t response_times[3] = {0, 0, 0};
  int timeout = 0;

  while (received_packets < 3) {
    int ready = select(sockfd + 1, &descriptors, NULL, NULL, &tv);

    if (ready < 0) {
      fprintf(stderr, "select error on recvfrom: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    // timeout (exceeded 1 second)
    if (ready == 0) {
      debug("%s", "timeout on select");
      timeout++;
      break;
    }

    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[IP_MAXPACKET];

    ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0,
                                  (struct sockaddr *)&sender, &sender_len);
    if (packet_len < 0) {
      fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    struct ip *ip_header = (struct ip *)buffer;
    ssize_t ip_header_len = (uint)4 * ip_header->ip_hl;
    u_int8_t *icmp_packet = buffer + ip_header_len;
    struct icmp *icmp_header = (struct icmp *)icmp_packet;

    char sender_ip_str[20];
    // returns non-null pointer on success
    if (!inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str,
                   sizeof(sender_ip_str))) {
      fprintf(stderr, "inet_ntop error (getting sender ip): %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    };

    debug("Received IP packet with ICMP content from: %s\n", sender_ip_str);

    if (!is_correct_packet(icmp_header, pid, seq_arr)) continue;

    uint64_t ms = (uint64_t)((1000000 - tv.tv_usec) / 1000);
    debug("time: %ld ms", ms);

    strcpy(ip_addresses[received_packets], sender_ip_str);
    response_times[received_packets] = ms;
    received_packets++;
  }

  debug("received packets: %d", received_packets);

  return build_output(ip_addresses, response_times, timeout, goal_address);
}