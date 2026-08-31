
Use the non scapy version of the py file (raw pdu) inside du container and run
python3 generate_raw_pdu_1.py
inside docker container of DU.

For this, add NET_Raw capability in the du-pci0
It will send the PDU type 1 packet out of the eth0 interface of Du so it will come inside the eth0 of CU