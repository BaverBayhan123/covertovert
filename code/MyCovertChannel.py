import time
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sniff
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        self.binary_message = ''  # Persistent binary message accumulator
        self.decoded_message = ''  # Persistent decoded message
        self.should_stop = False  # stop flag
        self.secret = ''          # secret number for XOR encryption
        self.dividend = ''        # dividend for division-based encryption
        pass

    def send(self, log_file_name, secret, dividend, dport, sport):
        """
        Sends a covert message byte by byte using the ACK flag and encryption logic.

        This function generates a random binary message, encodes it using a combination of XOR with a secret and
        division by a dividend, and sends each encoded byte bit-by-bit exploiting the ACK flag in TCP packets.
        The covert channel capacity achieved by this function is approximately ~49.23727 bits per second.

        :param log_file_name: Name of the log file for storing the generated random message.
        :param secret: Binary string used as a key for XOR encryption.
        :param dividend: Binary string used for the division operation in the encoding logic.
        :param dport: Destination port number for TCP packets.
        :param sport: Source port number for TCP packets.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16)
        start_time = time.time()
        secret_binary = int(secret, 2)
        dividend_binary = int(dividend, 2)
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i + 8]

            # Encoding logic
            b1 = int(byte, 2)
            b2 = b1 ^ secret_binary  # XOR with secret
            quotient = b2 // dividend_binary
            modulo = b2 % dividend_binary
            b3 = (quotient << 3) | modulo  # Combine quotient and modulo into a single byte
            encoded_byte = format(b3, '08b')

            # Transmit the encoded byte bit-by-bit using the ACK flag
            for bit in encoded_byte:
                ack_flag = 0x10 if bit == '1' else 0x00  # Set ACK flag
                pkt = IP(dst="receiver") / TCP(flags=ack_flag, dport=dport, sport=sport)
                super().send(pkt)

        end_time = time.time()
        elapsed_time = end_time - start_time
        covert_channel_capacity = len(binary_message) / elapsed_time
        # print(f"Covert Channel Capacity: {covert_channel_capacity:.5f} bits per second")


    def receive(self, log_file_name, secret, dividend, dport, sport):
        """
        Receives and decodes the transmitted message by interpreting the ACK flag.

        This function captures TCP packets and decodes the covert message sent by manipulating the ACK flag.
        It uses the same secret and dividend as the sender to reverse the encoding logic and reconstruct the original message.
        The sniffing functionality ensures that only relevant packets are captured, and the decoding stops when a termination
        character (`.`) is received.

        :param log_file_name: Name of the log file for storing the decoded message.
        :param secret: Binary string used as a key for XOR decryption.
        :param dividend: Binary string used for reversing the division operation in the decoding logic.
        :param dport: Destination port number to filter incoming TCP packets.
        :param sport: Source port number to filter incoming TCP packets.
        """
        self.binary_message = ''
        self.decoded_message = ''
        self.secret = secret
        self.dividend = dividend


        sniff(filter=f"tcp and src port {sport} and dst port {dport}",
              prn=self.packet_handler,
              stop_filter=self.stop_filter,
              store = False)

        # Log the final decoded message
        super().log_message(self.decoded_message, log_file_name)

    def stop_filter(self, packet):
        """
        Determines whether sniffing should stop.

        :param packet: The sniffed packet.
        :return: True if the termination character (`.`) has been received, False otherwise.
        """
        return self.should_stop


    def packet_handler(self, packet):
        """
        Handles each packet to decode the message using the ACK flag.

        :param packet: The sniffed packet.
        """
        secret_binary = int(self.secret, 2)
        dividend_binary = int(self.dividend, 2)
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            ack_flag = tcp_layer.flags & 0x10
            bit = '1' if (ack_flag == 0x10) else '0'
            self.binary_message += bit

            if len(self.binary_message) == 8:
                encoded_byte = int(self.binary_message, 2)

                # decode message
                b3 = encoded_byte
                quotient = (b3 >> 3) & 0x1F
                modulo = b3 & 0x07
                b2 = (quotient * dividend_binary) + modulo
                b1 = b2 ^ secret_binary
                char = chr(b1)
                self.decoded_message += char

                # Check for termination BEFORE clearing binary_message
                if char == '.':
                    self.should_stop = True

                self.binary_message = ''
