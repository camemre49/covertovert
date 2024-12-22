from scapy.all import ARP, Ether, sendp, sniff
from CovertChannelBase import CovertChannelBase
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def send(self, log_file_name, parameter1, parameter2):
        """
        Sends binary-encoded ARP packets.
        Each bit is encoded as a specific destination IP address in an ARP request.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        # Start the timer
        start_time = time.time()
        for bit in binary_message:
            # Set target IP based on the bit ('1' or '0')
            target_ip = parameter1 if bit == '1' else parameter2

            # Construct the ARP packet
            packet = Ether() / ARP(
                pdst=target_ip     # Destination IP encoding the bit
            )

            sendp(packet, verbose=False)
        # End the timer
        end_time = time.time()
        # Calculate the time taken in seconds
        # print("Elapsed time: ", end_time - start_time)
        # print("Capacity: ", (end_time - start_time) / len(binary_message))

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        Listens for ARP packets and decodes the binary message from their destination IP field.
        Stops capturing when the dot character ('.') is received.
        """
        binary_message = ""
        message = ""
        stop_sniffing = False

        def process_packet(packet):
            nonlocal binary_message, stop_sniffing, message

            if packet.haslayer(ARP):
                # Decode the bit based on the destination IP address
                if packet.pdst == parameter1:
                    binary_message += '1'
                elif packet.pdst == parameter2:
                    binary_message += '0'

                # Check if a complete byte has been received
                if len(binary_message) % 8 == 0:
                    byte = binary_message[-8:]
                    char = self.convert_eight_bits_to_character(byte)
                    message += char

                    # Check for the stopping character
                    if char == '.':
                        stop_sniffing = True

        # Start sniffing ARP packets
        sniff(filter="arp", prn=process_packet, stop_filter=lambda p: stop_sniffing)

        self.log_message(message, log_file_name)




