import socket, struct, time

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(("eth0", 0))

with open("output.pcap", "wb") as f:
    f.write(struct.pack("IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    try:
        while True:
            packet = s.recvfrom(65535)[0]
            ts_sec = int(time.time())
            f.write(struct.pack("IIII", ts_sec, 0, len(packet), len(packet)))
            f.write(packet)
    except KeyboardInterrupt:
        pass