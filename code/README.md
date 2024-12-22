# Covert Storage Channel that exploits Protocol Field Manipulation using Destination IP Address field in ARP

# Capacity ~= 0.08

Our implementation demonstrates a *Covert Storage Channel* that exploits the *Destination IP Address* field in *ARP (Address Resolution Protocol)* requests to covertly send binary data. 

### Implementation:
- *Sender: Encodes a binary message by manipulating the **Destination IP Address* in ARP packets. For each bit of data:
  - *Bit '1'*: The destination IP is set to parameter1 (e.g., 192.168.1.1).
  - *Bit '0'*: The destination IP is set to parameter2 (e.g., 192.168.1.2).
  
- *Receiver*: Listens for ARP requests and decodes the binary data by checking the destination IP address. It reconstructs the message by grouping bits into bytes and converting them into characters.

### Performance:
- *Capacity*: The channel has transmission rate around ~0.08.
