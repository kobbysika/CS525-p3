# Project 3: IPv4 Routing Table

- Name: Perry Aryee
- Email: perryaryee@u.boisestate.edu
- Class: CS525 - 003

## Known Bugs or Issues

There are no known bugs or unresolved issues. The project builds and runs on
the required Linux environments. 

## Experience

I worked through this project task by task, testing each part before moving to
the next one. The regular subnet calculations were okay, but the
boundary cases required more attention. I had to make sure `/0`, `/31`, and `/32`
followed their special rules and that the program rejected malformed addresses
instead of trying to interpret them. I also learned why shifting a 32-bit value
by 32 is unsafe and why the `/0` host-count calculation must use 64-bit arithmetic.

The forwarding table was the most interesting part for me. I had to make sure the
table could grow without losing its existing routes and that an error did not
leave partially changed output. I also had to scan every matching route instead
of returning the first one, because the route with the longest prefix is the
correct result. Writing tests for invalid input, overlapping routes,
different insertion orders, and file-loading errors helped me understand the
code and catch cases that the normal examples did not show.

## Design

I stored each IPv4 address as a `uint32_t`, with the first octet in the
most significant byte. I wrote the parser to read and validate each octet
instead of using functions such as `inet_aton()` or `sscanf()`, because those
functions can accept formats that this project requires us to reject.
The CIDR parser uses the same address parser and then checks that the
prefix is a number from 0 through 32.

I used bit operations to calculate the subnet mask, network address,
broadcast address, and host range. I handled `/0` separately so the code
does not shift a 32-bit value by 32 positions. I used 64-bit arithmetic
for the host count because calculating the size of a `/0` temporarily requires
representing `2^32`. For a `/31`, both addresses are usable because it represents
a point-to-point link. A /32 represents one host, so its network, broadcast,
first-host, and last-host values are the same address.

I implemented the forwarding table as a dynamically allocated array that
doubles in capacity when it becomes full. The table rejects destinations with
host bits set and does not allow two routes for the same block. For a lookup,
I check every route that contains the destination and keep the route with the
longest prefix. This means the result does not depend on the order in which
the routes were added. The default route is stored as `0.0.0.0/0`, so it matches
every address but is only selected when there is no more specific route.

## Building and Testing

Build every configuration and run the Unity test suite with:

```bash
make clean
make all
make check
make report
```

The tests exercise every public function and provide 100% line coverage of
`src/lab.c`. On Linux, memory checks can be run with:

```bash
make leak
make leak-test
```

## Usage

Display subnet information:

```bash
./build/release/myapp info 132.178.227.11/25
```

Split a network into equal-size subnets:

```bash
./build/release/myapp split 192.168.1.0/24 4
```

Perform longest-prefix lookups using the example forwarding table:

```bash
./build/release/myapp lookup tables/example.txt \
  132.178.227.50 8.8.8.8 10.1.2.5 10.1.2.200
```
