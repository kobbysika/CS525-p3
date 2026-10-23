#define _POSIX_C_SOURCE 200809L

#include "lab.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
};

static bool parse_decimal(const char **cursor, unsigned int maximum,
                          unsigned int *value)
{
  const char *text = *cursor;
  unsigned int parsed = 0;

  if (text[0] < '0' || text[0] > '9') {
    return false;
  }
  if (text[0] == '0' && text[1] >= '0' && text[1] <= '9') {
    return false;
  }

  do {
    parsed = parsed * 10U + (unsigned int)(*text - '0');
    if (parsed > maximum) {
      return false;
    }
    ++text;
  } while (*text >= '0' && *text <= '9');

  *cursor = text;
  *value = parsed;
  return true;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  uint32_t parsed = 0;
  const char *cursor = text;

  if (text == NULL || addr == NULL) {
    return false;
  }

  for (unsigned int octet = 0; octet < 4U; ++octet) {
    unsigned int value;

    if (!parse_decimal(&cursor, 255U, &value)) {
      return false;
    }
    parsed = (parsed << 8U) | (uint32_t)value;

    if (octet < 3U) {
      if (*cursor != '.') {
        return false;
      }
      ++cursor;
    }
  }

  if (*cursor != '\0') {
    return false;
  }

  *addr = parsed;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned int)((addr >> 24U) & 0xffU),
                 (unsigned int)((addr >> 16U) & 0xffU),
                 (unsigned int)((addr >> 8U) & 0xffU),
                 (unsigned int)(addr & 0xffU));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  char address[IP_STR_LEN];
  const char *slash;
  const char *cursor;
  unsigned int prefix;
  uint32_t addr;
  size_t address_length;

  if (text == NULL || block == NULL) {
    return false;
  }

  slash = strchr(text, '/');
  if (slash == NULL) {
    return false;
  }

  address_length = (size_t)(slash - text);
  if (address_length == 0U || address_length >= sizeof(address)) {
    return false;
  }
  memcpy(address, text, address_length);
  address[address_length] = '\0';

  if (!ip_parse(address, &addr)) {
    return false;
  }

  cursor = slash + 1;
  if (!parse_decimal(&cursor, 32U, &prefix) || *cursor != '\0') {
    return false;
  }

  block->addr = addr;
  block->prefix = (uint8_t)prefix;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char address[IP_STR_LEN];
  unsigned int prefix = block.prefix > 32U ? 32U : block.prefix;

  ip_format(block.addr, address);
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address, prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0U) {
    return UINT32_C(0);
  }
  if (prefix >= 32U) {
    return UINT32_MAX;
  }
  return UINT32_MAX << (32U - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return cidr_network(block) | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);
  return block.prefix >= 31U ? network : network + UINT32_C(1);
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  return block.prefix >= 31U ? broadcast : broadcast - UINT32_C(1);
}

uint64_t cidr_host_count(cidr_t block)
{
  uint8_t prefix = block.prefix > 32U ? 32U : block.prefix;

  if (prefix == 32U) {
    return UINT64_C(1);
  }
  if (prefix == 31U) {
    return UINT64_C(2);
  }
  return (UINT64_C(1) << (32U - prefix)) - UINT64_C(2);
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return block.addr == cidr_network(block);
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  uint8_t added_bits = 0;
  uint32_t count = n;
  uint8_t new_prefix;
  uint64_t subnet_size;
  cidr_t result;

  if (out == NULL || !cidr_is_network(block) || n == 0U ||
      (n & (n - 1U)) != 0U || i >= n) {
    return false;
  }

  while (count > 1U) {
    ++added_bits;
    count >>= 1U;
  }

  if (block.prefix > 32U || added_bits > 32U - block.prefix) {
    return false;
  }

  new_prefix = (uint8_t)(block.prefix + added_bits);
  subnet_size = UINT64_C(1) << (32U - new_prefix);
  result.addr = block.addr + (uint32_t)((uint64_t)i * subnet_size);
  result.prefix = new_prefix;
  *out = result;
  return true;
}

static const char *skip_whitespace(const char *text)
{
  while (*text != '\0' && isspace((unsigned char)*text) != 0) {
    ++text;
  }
  return text;
}

static bool skip_field_separator(const char **cursor)
{
  if (**cursor != ' ' && **cursor != '\t') {
    return false;
  }
  while (**cursor == ' ' || **cursor == '\t') {
    ++*cursor;
  }
  return true;
}

static bool copy_field(const char **cursor, char *field, size_t capacity)
{
  const char *start = *cursor;
  size_t length;

  while (**cursor != '\0' && isspace((unsigned char)**cursor) == 0) {
    ++*cursor;
  }
  length = (size_t)(*cursor - start);
  if (length == 0U || length >= capacity) {
    return false;
  }

  memcpy(field, start, length);
  field[length] = '\0';
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  char destination[CIDR_STR_LEN];
  char gateway[IP_STR_LEN];
  char device[DEV_NAME_LEN];
  const char *cursor;
  route_t parsed;

  if (line == NULL || route == NULL) {
    return false;
  }

  cursor = skip_whitespace(line);
  if (!copy_field(&cursor, destination, sizeof(destination))) {
    return false;
  }
  if (!skip_field_separator(&cursor)) {
    return false;
  }
  if (!copy_field(&cursor, gateway, sizeof(gateway))) {
    return false;
  }
  if (!skip_field_separator(&cursor)) {
    return false;
  }
  if (!copy_field(&cursor, device, sizeof(device))) {
    return false;
  }
  if (*skip_whitespace(cursor) != '\0') {
    return false;
  }

  if (strcmp(destination, "default") == 0) {
    parsed.dest.addr = 0;
    parsed.dest.prefix = 0;
  } else if (!cidr_parse(destination, &parsed.dest) ||
             !cidr_is_network(parsed.dest)) {
    return false;
  }

  if (strcmp(gateway, "direct") == 0) {
    parsed.gateway = 0;
  } else if (!ip_parse(gateway, &parsed.gateway)) {
    return false;
  }

  memcpy(parsed.dev, device, strlen(device) + 1U);
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void)
{
  return calloc(1U, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table != NULL) {
    free(table->routes);
    free(table);
  }
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0U : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  route_t *grown;
  size_t new_capacity;

  if (table == NULL || route == NULL || !cidr_is_network(route->dest)) {
    return false;
  }

  for (size_t i = 0; i < table->count; ++i) {
    if (table->routes[i].dest.addr == route->dest.addr &&
        table->routes[i].dest.prefix == route->dest.prefix) {
      return false;
    }
  }

  if (table->count == table->capacity) {
    new_capacity = table->capacity == 0U ? 4U : table->capacity * 2U;
    grown = realloc(table->routes, new_capacity * sizeof(*grown));
    if (grown == NULL) { // GCOVR_EXCL_LINE
      return false; // GCOVR_EXCL_LINE
    }
    table->routes = grown;
    table->capacity = new_capacity;
  }

  table->routes[table->count] = *route;
  ++table->count;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  char *line = NULL;
  size_t capacity = 0;
  size_t line_number = 0;
  ssize_t length;

  if (bad_line != NULL) {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  while ((length = getline(&line, &capacity, in)) >= 0) {
    char *comment;
    const char *content;
    route_t route;

    (void)length;
    ++line_number;
    comment = strchr(line, '#');
    if (comment != NULL) {
      *comment = '\0';
    }
    content = skip_whitespace(line);
    if (*content == '\0') {
      continue;
    }
    if (!route_parse(content, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = line_number;
      }
      free(line);
      return false;
    }
  }

  free(line);
  if (ferror(in) != 0) { // GCOVR_EXCL_LINE
    return false; // GCOVR_EXCL_LINE
  }
  return true;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  const route_t *best = NULL;

  if (table == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < table->count; ++i) {
    const route_t *candidate = &table->routes[i];
    if (cidr_contains(candidate->dest, dest) &&
        (best == NULL || candidate->dest.prefix > best->dest.prefix)) {
      best = candidate;
    }
  }
  return best;
}
