# DNS Server Implementation

## Overview

This project implements a DNS server that can respond to DNS queries. There are two main components:

1. **Basic DNS Server** (port 2053): Dynamically resolves DNS queries by forwarding them to a real DNS server (default: 8.8.8.8)
2. **Forwarding DNS Server** (port 2054): Also forwards DNS queries to a real DNS server, with additional features for handling multiple questions

## Requirements

- Python 3.6 or higher

## Running the Servers

### Basic DNS Server

```bash
python dns_server.py
```

This will start a server on port 2053 that forwards DNS queries to Google's DNS server (8.8.8.8).

You can also specify a custom DNS resolver:

```bash
python dns_server.py 1.1.1.1 53
```

### Forwarding DNS Server

```bash
python dns_forwarding_server.py
```

This will start a server on port 2054 that forwards DNS queries to Google's DNS server (8.8.8.8).

You can also specify a custom DNS resolver:

```bash
python dns_forwarding_server.py 1.1.1.1 53
```

## Testing

### Using the Test Script

You can test the servers using the included test script:

```bash
# Test the basic DNS server (port 2053)
python test_dns_server.py example.com

# Test the forwarding DNS server (port 2054)
python test_dns_server.py example.com 2054
```

### Using dig (Linux/macOS)

```bash
# Test the basic DNS server
dig @localhost -p 2053 example.com

# Test the forwarding DNS server
dig @localhost -p 2054 example.com
```

### Using nslookup (Windows)

```bash
# Test the basic DNS server
nslookup example.com localhost:2053

# Test the forwarding DNS server
nslookup example.com localhost:2054
```

## Implementation Details

### DNS Message Format

The DNS message format follows RFC 1035 and consists of:

1. **Header**: Contains flags and counts for the different sections
2. **Question**: Contains the domain name being queried and the type of query
3. **Answer**: Contains the response records

### Basic DNS Server

The basic DNS server now forwards all DNS queries to a real DNS server (default: 8.8.8.8) and returns the actual responses. It can be configured to use a different DNS resolver through command-line arguments.

### Forwarding DNS Server

The forwarding DNS server provides additional functionality for handling multiple questions in a single DNS query. It splits them into separate queries, forwards each one, and then combines the responses.

## Differences Between the Servers

While both servers now forward DNS queries to real DNS servers, the forwarding server has additional functionality for handling multiple questions in a single DNS query, which is a more advanced feature of the DNS protocol.