#include <stdio.h>

#ifdef TEST
#define main main_exclude
#endif

int main(void)
{
  puts("Usage: myapp info <address>/<prefix>");
  puts("       myapp split <network>/<prefix> <count>");
  puts("       myapp lookup <table-file> <address>...");
  return 0;
}
