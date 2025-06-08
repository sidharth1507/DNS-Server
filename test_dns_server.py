#!/usr/bin/env python3

import socket
import struct
import sys

def create_dns_query(domain_name, record_type=1):
    """Create a DNS query packet for the specified domain name."""
    # Create a random transaction ID
    transaction_id = 1234
    
    # Create the header
    # Transaction ID (16 bits)
    # Flags (16 bits): Standard query (0x0000)
    # Questions (16 bits): 1
    # Answer RRs (16 bits): 0
    # Authority RRs (16 bits): 0
    # Additional RRs (16 bits): 0
    header = struct.pack('>HHHHHH', transaction_id, 0x0000, 1, 0, 0, 0)
    
    # Encode the domain name
    query = b''
    for part in domain_name.split('.'):
        query += struct.pack('B', len(part))
        query += part.encode('ascii')
    query += struct.pack('B', 0)  # Null terminator
    
    # Add the query type (A record = 1) and class (IN = 1)
    query += struct.pack('>HH', record_type, 1)
    
    return header + query

def parse_dns_response(response):
    """Parse a DNS response packet and print the details."""
    # Parse the header
    header = response[:12]
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', header)
    
    print(f"Transaction ID: {transaction_id}")
    print(f"Flags: 0x{flags:04x}")
    print(f"Questions: {qdcount}")
    print(f"Answer RRs: {ancount}")
    print(f"Authority RRs: {nscount}")
    print(f"Additional RRs: {arcount}")
    
    # Check if this is a response
    qr = (flags >> 15) & 0x1
    if qr != 1:
        print("Warning: This is not a response packet!")
    
    # Check the response code
    rcode = flags & 0xF
    if rcode != 0:
        print(f"Error: Response code is {rcode}")
        return
    
    # Skip the question section (we know what we asked)
    offset = 12
    for _ in range(qdcount):
        # Skip the domain name
        while True:
            length = response[offset]
            offset += 1
            if length == 0:
                break
            offset += length
        # Skip the query type and class
        offset += 4
    
    # Parse the answer section
    for i in range(ancount):
        print(f"\nAnswer {i+1}:")
        
        # Parse the domain name
        name_parts = []
        name_offset = offset
        
        while True:
            length = response[name_offset]
            name_offset += 1
            
            # Check if this is a pointer
            if (length & 0xC0) == 0xC0:
                pointer_offset = ((length & 0x3F) << 8) | response[name_offset]
                name_offset += 1
                print(f"  Name: <pointer to offset {pointer_offset}>")
                break
            
            # Check if we've reached the end of the domain name
            if length == 0:
                print(f"  Name: {'.'.join(name_parts)}")
                break
            
            # Extract the label
            label = response[name_offset:name_offset+length].decode('ascii')
            name_parts.append(label)
            name_offset += length
        
        offset = name_offset
        
        # Parse the record type, class, TTL, and data length
        record_type, record_class, ttl, data_length = struct.unpack('>HHIH', response[offset:offset+10])
        offset += 10
        
        print(f"  Type: {record_type}")
        print(f"  Class: {record_class}")
        print(f"  TTL: {ttl} seconds")
        print(f"  Data length: {data_length} bytes")
        
        # Parse the record data based on the record type
        if record_type == 1:  # A record
            ip_bytes = response[offset:offset+4]
            ip_address = '.'.join(str(b) for b in ip_bytes)
            print(f"  IP Address: {ip_address}")
        else:
            print(f"  Data: {response[offset:offset+data_length].hex()}")
        
        offset += data_length

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain_name> [port]")
        print(f"  domain_name: The domain name to query")
        print(f"  port: The port to connect to (default: 2053)")
        sys.exit(1)
    
    domain_name = sys.argv[1]
    port = 2053  # Default to the basic DNS server port
    
    # Check if a port was specified
    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print(f"Error: Invalid port number '{sys.argv[2]}'")
            sys.exit(1)
    
    server_address = ('localhost', port)
    
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)  # Set a timeout of 5 seconds
    
    try:
        # Create a DNS query
        query = create_dns_query(domain_name)
        
        print(f"Sending DNS query for {domain_name} to {server_address[0]}:{server_address[1]}...")
        
        # Send the query
        client_socket.sendto(query, server_address)
        
        # Receive the response
        response, _ = client_socket.recvfrom(512)  # DNS messages are limited to 512 bytes in UDP
        
        print(f"\nReceived response ({len(response)} bytes):")
        
        # Parse and print the response
        parse_dns_response(response)
        
    except socket.timeout:
        print("Error: Timeout waiting for response")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()