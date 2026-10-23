#include "harness/unity.h"
#include "../src/lab.h"

#include <stddef.h>
#include <stdint.h>

void setUp(void) {}
void tearDown(void) {}

void test_ip_parse_accepts_valid_addresses(void)
{
  uint32_t addr = 0;
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), addr);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFF), addr);
}

void test_ip_parse_rejects_malformed_addresses(void)
{
  static const char *const invalid[] = {
    "", "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1",
    "010.0.0.1", "1.2.3.4x", "+1.2.3.4", "1.2.3.-4",
    "1.2.3.04", "1.2.3.4 ", " 1.2.3.4"
  };
  uint32_t addr = UINT32_C(0x12345678);

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    TEST_ASSERT_FALSE(ip_parse(invalid[i], &addr));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), addr);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_ip_format_formats_all_octets(void)
{
  char text[IP_STR_LEN];
  ip_format(UINT32_C(0xC0A8010A), text);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", text);
  ip_format(UINT32_C(0), text);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", text);
  ip_format(UINT32_C(0xFFFFFFFF), text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", text);
}

void test_cidr_parse_accepts_valid_blocks(void)
{
  cidr_t block = {0, 0};
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.10/24", &block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), block.addr);
  TEST_ASSERT_EQUAL_UINT8(24, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);
}

void test_cidr_parse_rejects_malformed_blocks(void)
{
  static const char *const invalid[] = {
    "", "1.2.3.4", "/24", "1.2.3.4/", "1.2.3/24",
    "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/+2",
    "1.2.3.4/2x", "1.2.3.4/2/3", "255.255.255.2555/24"
  };
  cidr_t block = {UINT32_C(0x12345678), 17};

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    TEST_ASSERT_FALSE(cidr_parse(invalid[i], &block));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), block.addr);
    TEST_ASSERT_EQUAL_UINT8(17, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));
}

void test_cidr_format_preserves_address_and_clamps_prefix(void)
{
  char text[CIDR_STR_LEN];
  cidr_t block = {UINT32_C(0x84B2E30B), 25};
  cidr_format(block, text);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", text);

  block.addr = UINT32_C(0xFFFFFFFF);
  block.prefix = 99;
  cidr_format(block, text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", text);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_accepts_valid_addresses);
  RUN_TEST(test_ip_parse_rejects_malformed_addresses);
  RUN_TEST(test_ip_format_formats_all_octets);
  RUN_TEST(test_cidr_parse_accepts_valid_blocks);
  RUN_TEST(test_cidr_parse_rejects_malformed_blocks);
  RUN_TEST(test_cidr_format_preserves_address_and_clamps_prefix);
  return UNITY_END();
}
