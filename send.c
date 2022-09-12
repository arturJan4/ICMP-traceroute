// Artur Jankowski, 317928

#include "send.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Uncomment this line for debugging output */
//#define DEBUG
#ifdef DEBUG
#define debug(fmt, ...) printf("%s: " fmt "\n", __func__, __VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

// internal functions and vars marked static for gcc optimization
static struct icmp header;
static struct sockaddr_in recipient;

static u_int16_t compute_icmp_checksum(const void *buff, int length) {
  u_int32_t sum;
  const u_int16_t *ptr = buff;
  assert(length % 2 == 0);
  for (sum = 0; length > 0; length -= 2) sum += *ptr++;
  sum = (sum >> (uint)16) + (sum & (uint)0xffff);
  return (u_int16_t)(~(sum + (sum >> (uint)16)));
}

static void set_echo_header(int seqnum, uint16_t pid) {
  header.icmp_type = ICMP_ECHO;
  header.icmp_code = 0;
  header.icmp_hun.ih_idseq.icd_id = htons(pid);  // endianness change
  header.icmp_hun.ih_idseq.icd_seq = htons((uint16_t)seqnum);
  header.icmp_cksum = 0;
  header.icmp_cksum =
      compute_icmp_checksum((u_int16_t *)&header, sizeof(header));
}

static void set_recipient(char *ip_addr) {
  memset(&recipient, 0, sizeof(recipient));
  recipient.sin_family = AF_INET;

  int result = inet_pton(AF_INET, ip_addr, &recipient.sin_addr);
  if (result == 0) {
    fprintf(stderr, "%s is not a valid IPv4 address!\n", ip_addr);
    exit(EXIT_FAILURE);
  } else if (result < 0) {
    fprintf(stderr, "error during ip to binary conversion!: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
}

// send packet to addr with given TTL, and <seqnum, pid> for identification
void send_packet(int sockfd, char *addr, int ttl, int seqnum, uint16_t pid) {
  set_echo_header(seqnum, pid);

  // could be done only once (for traceroute),
  // but this adds unexpected complexity
  set_recipient(addr);

  if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) != 0) {
    fprintf(stderr, "Error setting TTL. %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  ssize_t bytes_sent = sendto(sockfd, &header, sizeof(header), 0,
                              (struct sockaddr *)&recipient, sizeof(recipient));

  debug("bytes sent: %ld, ttl: %d, seqnum: %d", bytes_sent, ttl, seqnum);

  if (bytes_sent != sizeof(header)) {
    fprintf(stderr, "Bytes sent don't match size of the header. %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
}
