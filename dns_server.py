#!/usr/bin/env python3

import socket
import struct
import sys

# Constants for DNS record types
A_RECORD_TYPE = 1
IN_CLASS = 1

# Default DNS resolver to forward requests to
DEFAULT_DNS_RESOLVER = ('8.8.8.8', 53)  # Google's public DNS

class DNSHeader:
    def __init__(self, id=0, qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0,
                 qdcount=0, ancount=0, nscount=0, arcount=0):
        self.id = id            # 16 bits: Packet Identifier
        self.qr = qr            # 1 bit: Query/Response Indicator
        self.opcode = opcode    # 4 bits: Operation Code
        self.aa = aa            # 1 bit: Authoritative Answer
        self.tc = tc            # 1 bit: Truncation
        self.rd = rd            # 1 bit: Recursion Desired
        self.ra = ra            # 1 bit: Recursion Available
        self.z = z              # 3 bits: Reserved
        self.rcode = rcode      # 4 bits: Response Code
        self.qdcount = qdcount  # 16 bits: Question Count
        self.ancount = ancount  # 16 bits: Answer Record Count
        self.nscount = nscount  # 16 bits: Authority Record Count
        self.arcount = arcount  # 16 bits: Additional Record Count

    def pack(self):
        # Pack the first 16 bits: ID
        header = struct.pack('>H', self.id)
        
        # Pack the next 16 bits: QR (1), OPCODE (4), AA (1), TC (1), RD (1), RA (1), Z (3), RCODE (4)
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | \
                (self.z << 4) | self.rcode
        header += struct.pack('>H', flags)
        
        # Pack the remaining fields
        header += struct.pack('>HHHH', self.qdcount, self.ancount, self.nscount, self.arcount)
        
        return header

    @classmethod
    def unpack(cls, data):
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])
        
        # Extract the individual flag bits
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        
        return cls(id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount)

class DNSQuestion:
    def __init__(self, name='', qtype=0, qclass=0):
        self.name = name      # Domain name
        self.qtype = qtype    # Query type
        self.qclass = qclass  # Query class

    def pack(self):
        # Pack the domain name
        question = self.pack_domain_name(self.name)
        
        # Pack the type and class
        question += struct.pack('>HH', self.qtype, self.qclass)
        
        return question

    @staticmethod
    def pack_domain_name(domain_name):
        result = b''
        
        # Split the domain name into labels
        labels = domain_name.split('.')
        
        # Pack each label
        for label in labels:
            result += struct.pack('B', len(label))
            result += label.encode('ascii')
        
        # Terminate with a null byte
        result += struct.pack('B', 0)
        
        return result

    @classmethod
    def unpack(cls, data, offset):
        name, offset = cls.unpack_domain_name(data, offset)
        qtype, qclass = struct.unpack('>HH', data[offset:offset+4])
        
        return cls(name, qtype, qclass), offset + 4

    @staticmethod
    def unpack_domain_name(data, offset):
        name_parts = []
        original_offset = offset
        
        while True:
            length = data[offset]
            offset += 1
            
            # Check if this is a pointer (compression)
            if (length & 0xC0) == 0xC0:
                pointer_offset = ((length & 0x3F) << 8) | data[offset]
                offset += 1
                
                # Recursively unpack the domain name from the pointer location
                pointed_name, _ = DNSQuestion.unpack_domain_name(data, pointer_offset)
                name_parts.append(pointed_name)
                break
            
            # Check if we've reached the end of the domain name
            if length == 0:
                break
            
            # Extract the label
            label = data[offset:offset+length].decode('ascii')
            name_parts.append(label)
            offset += length
        
        return '.'.join(filter(None, name_parts)), offset

class DNSRecord:
    def __init__(self, name='', record_type=0, record_class=0, ttl=0, rdata=b''):
        self.name = name              # Domain name
        self.record_type = record_type  # Record type
        self.record_class = record_class  # Record class
        self.ttl = ttl                # Time to live
        self.rdata = rdata            # Resource data

    def pack(self):
        # Pack the domain name
        record = DNSQuestion.pack_domain_name(self.name)
        
        # Pack the type, class, TTL, and data length
        record += struct.pack('>HHIH', self.record_type, self.record_class, self.ttl, len(self.rdata))
        
        # Pack the data
        record += self.rdata
        
        return record

    @classmethod
    def unpack(cls, data, offset):
        name, offset = DNSQuestion.unpack_domain_name(data, offset)
        record_type, record_class, ttl, data_length = struct.unpack('>HHIH', data[offset:offset+10])
        offset += 10
        
        rdata = data[offset:offset+data_length]
        
        return cls(name, record_type, record_class, ttl, rdata), offset + data_length

class DNSMessage:
    def __init__(self, header=None, questions=None, answers=None):
        self.header = header or DNSHeader()
        self.questions = questions or []
        self.answers = answers or []

    def pack(self):
        # Pack the header
        message = self.header.pack()
        
        # Pack the questions
        for question in self.questions:
            message += question.pack()
        
        # Pack the answers
        for answer in self.answers:
            message += answer.pack()
        
        return message

    @classmethod
    def unpack(cls, data):
        # Unpack the header
        header = DNSHeader.unpack(data)
        
        # Initialize the message
        message = cls(header)
        
        # Start parsing from after the header
        offset = 12
        
        # Unpack the questions
        for _ in range(header.qdcount):
            question, offset = DNSQuestion.unpack(data, offset)
            message.questions.append(question)
        
        # Unpack the answers
        for _ in range(header.ancount):
            answer, offset = DNSRecord.unpack(data, offset)
            message.answers.append(answer)
        
        return message

def forward_dns_query(query_data, dns_resolver=DEFAULT_DNS_RESOLVER):
    """Forward a DNS query to another DNS server and return the response."""
    # Create a UDP socket for forwarding
    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_socket.settimeout(5)  # Set a timeout of 5 seconds
    
    try:
        # Send the query to the DNS resolver
        forward_socket.sendto(query_data, dns_resolver)
        
        # Receive the response
        response_data, _ = forward_socket.recvfrom(4096)  # Increased buffer size for larger responses
        
        return response_data
    except socket.timeout:
        print("Timeout forwarding DNS query")
        return None
    except Exception as e:
        print(f"Error forwarding DNS query: {e}")
        return None
    finally:
        forward_socket.close()

def create_response(request_data, dns_resolver=DEFAULT_DNS_RESOLVER):
    """Create a response to a DNS query by forwarding it to a real DNS server."""
    # Parse the request
    request = DNSMessage.unpack(request_data)
    
    # Forward the request to a real DNS server
    response_data = forward_dns_query(request_data, dns_resolver)
    
    if response_data:
        # If we got a response, return it
        return response_data
    else:
        # If forwarding failed, create an error response
        error_header = DNSHeader(
            id=request.header.id,
            qr=1,  # This is a response
            opcode=request.header.opcode,
            aa=0,
            tc=0,
            rd=request.header.rd,
            ra=0,
            z=0,
            rcode=2,  # Server failure
            qdcount=len(request.questions),
            ancount=0,
            nscount=0,
            arcount=0
        )
        
        error_response = DNSMessage(
            header=error_header,
            questions=request.questions
        )
        
        return error_response.pack()

def main():
    # Parse command-line arguments for custom DNS resolver
    dns_resolver = DEFAULT_DNS_RESOLVER
    if len(sys.argv) > 2:
        dns_resolver = (sys.argv[1], int(sys.argv[2]))
    
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 2053))
    
    print(f"DNS Server started on port 2053, using resolver {dns_resolver[0]}:{dns_resolver[1]}")
    
    try:
        while True:
            # Receive data from client
            request_data, client_address = server_socket.recvfrom(512)  # DNS messages are limited to 512 bytes in UDP
            
            # Create a response
            response_data = create_response(request_data, dns_resolver)
            
            # Send the response back to the client
            server_socket.sendto(response_data, client_address)
    except KeyboardInterrupt:
        print("\nShutting down DNS server...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()