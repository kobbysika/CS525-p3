#include "lab.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(void)
{
  puts("Usage: myapp info <address>/<prefix>");
  puts("       myapp split <network>/<prefix> <count>");
  puts("       myapp lookup <table-file> <address>...");
}

static int command_info(const char *text)
{
  cidr_t block;
  char address[IP_STR_LEN];
  char netmask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first_host[IP_STR_LEN];
  char last_host[IP_STR_LEN];

  if (!cidr_parse(text, &block)) {
    fprintf(stderr, "myapp: %s: not a valid address/prefix\n", text);
    return 1;
  }

  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), netmask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first_host);
  ip_format(cidr_last_host(block), last_host);

  printf("address    %s\n", address);
  printf("prefix     /%u\n", (unsigned int)block.prefix);
  printf("netmask    %s\n", netmask);
  printf("network    %s\n", network);
  printf("broadcast  %s\n", broadcast);
  printf("first host %s\n", first_host);
  printf("last host  %s\n", last_host);
  printf("hosts      %" PRIu64 "\n", cidr_host_count(block));
  return 0;
}

static bool parse_count(const char *text, uint32_t *count)
{
  char *end;
  unsigned long value;

  if (text == NULL || *text == '\0' || text[0] == '-' || text[0] == '+') {
    return false;
  }
  errno = 0;
  value = strtoul(text, &end, 10);
  if (errno != 0 || *end != '\0' || value == 0UL || value > UINT32_MAX) {
    return false;
  }
  *count = (uint32_t)value;
  return true;
}

static int command_split(const char *text, const char *count_text)
{
  cidr_t block;
  uint32_t count;

  if (!cidr_parse(text, &block)) {
    fprintf(stderr, "myapp: %s: not a valid address/prefix\n", text);
    return 1;
  }
  if (!cidr_is_network(block)) {
    fprintf(stderr, "myapp: %s: host bits must be zero\n", text);
    return 1;
  }
  if (!parse_count(count_text, &count) || (count & (count - 1U)) != 0U) {
    fprintf(stderr, "myapp: %s: subnet count must be a power of two\n",
            count_text);
    return 1;
  }

  for (uint32_t i = 0; i < count; ++i) {
    cidr_t subnet;
    char formatted[CIDR_STR_LEN];

    if (!cidr_subnet(block, count, i, &subnet)) {
      fprintf(stderr, "myapp: cannot split %s into %" PRIu32 " subnets\n",
              text, count);
      return 1;
    }
    cidr_format(subnet, formatted);
    puts(formatted);
  }
  return 0;
}

static int load_table(const char *path, fwd_table_t *table)
{
  FILE *file = fopen(path, "r");
  size_t bad_line = 0;

  if (file == NULL) {
    fprintf(stderr, "myapp: %s: cannot open forwarding table\n", path);
    return 2;
  }
  if (!table_load(table, file, &bad_line)) {
    if (bad_line == 0U) {
      fprintf(stderr, "myapp: %s: could not read forwarding table\n", path);
    } else {
      fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path, bad_line);
    }
    (void)fclose(file);
    return 2;
  }
  if (fclose(file) != 0) {
    fprintf(stderr, "myapp: %s: could not close forwarding table\n", path);
    return 2;
  }
  return 0;
}

static int command_lookup(const char *path, int address_count,
                          char *const addresses[])
{
  fwd_table_t *table = table_create();
  bool malformed = false;
  bool unreachable = false;
  int load_status;

  if (table == NULL) {
    fputs("myapp: could not allocate forwarding table\n", stderr);
    return 2;
  }
  load_status = load_table(path, table);
  if (load_status != 0) {
    table_destroy(table);
    return load_status;
  }

  for (int i = 0; i < address_count; ++i) {
    uint32_t destination;
    const route_t *route;

    if (!ip_parse(addresses[i], &destination)) {
      fprintf(stderr, "myapp: %s: not a valid address\n", addresses[i]);
      malformed = true;
      continue;
    }

    route = table_lookup(table, destination);
    if (route == NULL) {
      printf("%s unreachable\n", addresses[i]);
      unreachable = true;
    } else if (route->gateway == 0U) {
      printf("%s dev %s\n", addresses[i], route->dev);
    } else {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      printf("%s via %s dev %s\n", addresses[i], gateway, route->dev);
    }
  }

  table_destroy(table);
  if (malformed) {
    return 1;
  }
  return unreachable ? 3 : 0;
}

int main(int argc, char *argv[])
{
  if (argc == 1) {
    print_usage();
    return 0;
  }

  if (strcmp(argv[1], "info") == 0 && argc == 3) {
    return command_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0 && argc == 4) {
    return command_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0 && argc >= 4) {
    return command_lookup(argv[2], argc - 3, &argv[3]);
  }

  fputs("myapp: invalid command line\n", stderr);
  print_usage();
  return 1;
}
