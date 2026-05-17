import dns.message
import socket
import time

# Use this script if you don't have dig installed
# Otherwise use dig @127.0.0.1 -p 5354 google.com A

# Changeable params
PORT = 5354
query_url = "google.com"
rdata_type = "A"

query = dns.message.make_query(query_url, rdata_type)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
now = time.time() * 1000
s.sendto(query.to_wire(), ("127.0.0.1", PORT))
data, _ = s.recvfrom(4096)
response = dns.message.from_wire(data)
response_time = str(round(time.time() * 1000 - now, 2))
print(response)
print("query time: " + response_time + "ms")