#include "lab.h"

#include <stdio.h>
#include <string.h>

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
