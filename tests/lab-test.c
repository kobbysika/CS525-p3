#include "harness/unity.h"
#include "../src/lab.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

void test_cidr_mask_handles_every_boundary(void)
{
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x80000000), cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFF00), cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(99));
}

void test_cidr_network_and_broadcast_clear_and_set_host_bits(void)
{
  cidr_t block = {UINT32_C(0x84B2E30B), 25};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E300), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E37F), cidr_broadcast(block));

  block.addr = UINT32_C(0x12345678);
  block.prefix = 0;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(block));
}

void test_cidr_host_ranges_handle_regular_31_and_32_blocks(void)
{
  cidr_t block = {UINT32_C(0xC0A8010A), 24};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A80101), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A801FE), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(254), cidr_host_count(block));

  block.addr = UINT32_C(0xC0A8010B);
  block.prefix = 31;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010B), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(2), cidr_host_count(block));

  block.prefix = 32;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010B), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010B), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(1), cidr_host_count(block));

  block.prefix = 99;
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(1), cidr_host_count(block));
}

void test_cidr_host_count_uses_64_bit_arithmetic_for_default_route(void)
{
  cidr_t block = {0, 0};
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(1), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), cidr_last_host(block));
}

void test_cidr_contains_and_is_network(void)
{
  cidr_t block = {UINT32_C(0x0A010200), 24};
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x0A010200)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x0A0102FF)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0x0A010300)));
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block.addr = UINT32_C(0x0A010201);
  TEST_ASSERT_FALSE(cidr_is_network(block));

  block.addr = UINT32_C(0xDEADBEEF);
  block.prefix = 0;
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_MAX));
  TEST_ASSERT_FALSE(cidr_is_network(block));
}

void test_cidr_subnet_returns_requested_equal_subnet(void)
{
  cidr_t block = {UINT32_C(0xC0A80100), 24};
  cidr_t subnet = {0, 0};

  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A80100), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A801C0), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);

  TEST_ASSERT_TRUE(cidr_subnet(block, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(block.addr, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(block.prefix, subnet.prefix);
}

void test_cidr_subnet_supports_a_very_large_legal_split(void)
{
  cidr_t block = {0, 0};
  cidr_t subnet = {0, 0};
  uint32_t n = UINT32_C(1) << 31U;

  TEST_ASSERT_TRUE(cidr_subnet(block, n, n - 1U, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(31, subnet.prefix);
}

void test_cidr_subnet_rejects_invalid_requests_without_changing_output(void)
{
  cidr_t network = {UINT32_C(0xC0A80100), 24};
  cidr_t host_block = {UINT32_C(0xC0A80105), 24};
  cidr_t too_small = {UINT32_C(0xC0A80100), 31};
  cidr_t invalid_prefix = {UINT32_C(0xC0A80100), 33};
  cidr_t sentinel = {UINT32_C(0x12345678), 17};

  TEST_ASSERT_FALSE(cidr_subnet(network, 4, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet(host_block, 4, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(network, 0, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(network, 3, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(network, 4, 4, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(too_small, 4, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(invalid_prefix, 1, 0, &sentinel));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), sentinel.addr);
  TEST_ASSERT_EQUAL_UINT8(17, sentinel.prefix);
}

void test_route_parse_accepts_default_direct_and_whitespace(void)
{
  route_t route;

  TEST_ASSERT_TRUE(route_parse("  default\t132.178.227.1  eno1\n", &route));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E301), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);

  TEST_ASSERT_TRUE(route_parse("10.1.2.0/24 direct eth2", &route));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010200), route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(24, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", route.dev);

  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 direct abcdefghijklmno", &route));
  TEST_ASSERT_EQUAL_STRING("abcdefghijklmno", route.dev);
}

void test_route_parse_rejects_bad_lines_without_changing_output(void)
{
  static const char *const invalid[] = {
    "", "default direct", "default direct eth0 extra",
    "10.1.2.5/24 direct eth0", "10.0.0.0/8 bad eth0",
    "10.0.0.0/8 direct abcdefghijklmnop",
    "10.0.0.000000/8 direct eth0", "default 1.2.3.4 ",
    "default\ndirect eth0", "default direct\neth0"
  };
  route_t sentinel = {{UINT32_C(0x12345678), 17},
                      UINT32_C(0x87654321), "unchanged"};
  route_t route;

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    route = sentinel;
    TEST_ASSERT_FALSE(route_parse(invalid[i], &route));
    TEST_ASSERT_EQUAL_MEMORY(&sentinel, &route, sizeof(route));
  }
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
}

static route_t make_route(uint32_t addr, uint8_t prefix, uint32_t gateway,
                          const char *device)
{
  route_t route = {{addr, prefix}, gateway, ""};
  (void)snprintf(route.dev, sizeof(route.dev), "%s", device);
  return route;
}

void test_table_create_add_count_and_destroy(void)
{
  fwd_table_t *table = table_create();
  route_t routes[] = {
    make_route(UINT32_C(0), 0, UINT32_C(0x01010101), "eth0"),
    make_route(UINT32_C(0x0A000000), 8, 0, "eth1"),
    make_route(UINT32_C(0x0A010000), 16, 0, "eth2"),
    make_route(UINT32_C(0x0A010200), 24, 0, "eth3"),
    make_route(UINT32_C(0xC0A80000), 16, 0, "eth4")
  };

  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  TEST_ASSERT_EQUAL_size_t(0, table_count(NULL));
  TEST_ASSERT_FALSE(table_add(NULL, &routes[0]));
  TEST_ASSERT_FALSE(table_add(table, NULL));

  for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) {
    TEST_ASSERT_TRUE(table_add(table, &routes[i]));
  }
  TEST_ASSERT_EQUAL_size_t(5, table_count(table));
  table_destroy(table);
  table_destroy(NULL);
}

void test_table_add_rejects_duplicate_and_non_network_routes(void)
{
  fwd_table_t *table = table_create();
  route_t route = make_route(UINT32_C(0x0A000000), 8, 0, "eth0");
  route_t duplicate = make_route(UINT32_C(0x0A000000), 8,
                                 UINT32_C(0x01020304), "eth9");
  route_t host = make_route(UINT32_C(0x0A000001), 8, 0, "eth1");

  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_FALSE(table_add(table, &duplicate));
  TEST_ASSERT_FALSE(table_add(table, &host));
  TEST_ASSERT_EQUAL_size_t(1, table_count(table));
  table_destroy(table);
}

void test_table_load_handles_comments_blank_lines_and_routes(void)
{
  FILE *file = tmpfile();
  fwd_table_t *table = table_create();
  size_t bad_line = 99;

  TEST_ASSERT_NOT_NULL(file);
  TEST_ASSERT_NOT_NULL(table);
  (void)fputs("# comment only\n\n", file);
  (void)fputs("default 192.0.2.1 eth0\n", file);
  (void)fputs("10.0.0.0/8 direct eth1 # inline comment\n", file);
  rewind(file);

  TEST_ASSERT_TRUE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  (void)fclose(file);
  table_destroy(table);
}

void test_table_load_reports_first_bad_line_and_keeps_prior_routes(void)
{
  FILE *file = tmpfile();
  fwd_table_t *table = table_create();
  size_t bad_line = 0;

  TEST_ASSERT_NOT_NULL(file);
  TEST_ASSERT_NOT_NULL(table);
  (void)fputs("10.0.0.0/8 direct eth1\n", file);
  (void)fputs("10.1.0.0/16 direct eth2\n", file);
  (void)fputs("not a valid route\n", file);
  (void)fputs("10.1.2.0/24 direct eth3\n", file);
  rewind(file);

  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(3, bad_line);
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  (void)fclose(file);
  table_destroy(table);
}

void test_table_load_rejects_null_arguments(void)
{
  FILE *file = tmpfile();
  fwd_table_t *table = table_create();
  size_t bad_line = 99;

  TEST_ASSERT_NOT_NULL(file);
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_FALSE(table_load(NULL, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  bad_line = 99;
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_TRUE(table_load(table, file, NULL));
  (void)fclose(file);
  table_destroy(table);
}

static void add_lookup_routes(fwd_table_t *table, bool reverse)
{
  route_t routes[] = {
    make_route(UINT32_C(0), 0, UINT32_C(0xC0000201), "default"),
    make_route(UINT32_C(0x0A000000), 8, 0, "eight"),
    make_route(UINT32_C(0x0A010000), 16, 0, "sixteen"),
    make_route(UINT32_C(0x0A010200), 24, 0, "twentyfour"),
    make_route(UINT32_C(0x0A010280), 25, 0, "twentyfive")
  };
  size_t count = sizeof(routes) / sizeof(routes[0]);

  for (size_t i = 0; i < count; ++i) {
    size_t index = reverse ? count - 1U - i : i;
    TEST_ASSERT_TRUE(table_add(table, &routes[index]));
  }
}

void test_table_lookup_uses_longest_prefix_regardless_of_order(void)
{
  fwd_table_t *forward = table_create();
  fwd_table_t *reverse = table_create();
  const route_t *result;

  TEST_ASSERT_NOT_NULL(forward);
  TEST_ASSERT_NOT_NULL(reverse);
  add_lookup_routes(forward, false);
  add_lookup_routes(reverse, true);

  result = table_lookup(forward, UINT32_C(0x0A0102C8));
  TEST_ASSERT_NOT_NULL(result);
  TEST_ASSERT_EQUAL_UINT8(25, result->dest.prefix);
  result = table_lookup(reverse, UINT32_C(0x0A0102C8));
  TEST_ASSERT_NOT_NULL(result);
  TEST_ASSERT_EQUAL_UINT8(25, result->dest.prefix);

  result = table_lookup(forward, UINT32_C(0x08080808));
  TEST_ASSERT_NOT_NULL(result);
  TEST_ASSERT_EQUAL_UINT8(0, result->dest.prefix);
  TEST_ASSERT_NULL(table_lookup(NULL, UINT32_C(0)));
  table_destroy(forward);
  table_destroy(reverse);
}

void test_table_lookup_returns_null_without_a_matching_route(void)
{
  fwd_table_t *table = table_create();
  route_t route = make_route(UINT32_C(0x0A000000), 8, 0, "eth0");

  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0x0A000001)));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0xC0A80101)));
  TEST_ASSERT_NOT_NULL(table_lookup(table, UINT32_C(0x0AFFFFFF)));
  table_destroy(table);
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
  RUN_TEST(test_cidr_mask_handles_every_boundary);
  RUN_TEST(test_cidr_network_and_broadcast_clear_and_set_host_bits);
  RUN_TEST(test_cidr_host_ranges_handle_regular_31_and_32_blocks);
  RUN_TEST(test_cidr_host_count_uses_64_bit_arithmetic_for_default_route);
  RUN_TEST(test_cidr_contains_and_is_network);
  RUN_TEST(test_cidr_subnet_returns_requested_equal_subnet);
  RUN_TEST(test_cidr_subnet_supports_a_very_large_legal_split);
  RUN_TEST(test_cidr_subnet_rejects_invalid_requests_without_changing_output);
  RUN_TEST(test_route_parse_accepts_default_direct_and_whitespace);
  RUN_TEST(test_route_parse_rejects_bad_lines_without_changing_output);
  RUN_TEST(test_table_create_add_count_and_destroy);
  RUN_TEST(test_table_add_rejects_duplicate_and_non_network_routes);
  RUN_TEST(test_table_load_handles_comments_blank_lines_and_routes);
  RUN_TEST(test_table_load_reports_first_bad_line_and_keeps_prior_routes);
  RUN_TEST(test_table_load_rejects_null_arguments);
  RUN_TEST(test_table_lookup_uses_longest_prefix_regardless_of_order);
  RUN_TEST(test_table_lookup_returns_null_without_a_matching_route);
  return UNITY_END();
}
