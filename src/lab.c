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
