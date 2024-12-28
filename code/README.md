# Covert Storage Channel that exploits Protocol Field Manipulation using ACK Flag field in TCP [CSC-PSV-TCP-ACK]

A covert channel is a method of secretly transmitting data by exploiting unintended system features, such as timing differences or protocol fields, outside normal communication channels. It bypasses security controls and is often used to leak or hide information.

We have implemented a covert communication channel using TCP's ACK flag to encode and transmit data securely and covertly. The sender generates a random binary message, encrypts it using XOR with a secret key, and applies modular arithmetic to encode each byte. Each encoded byte is transmitted bit-by-bit by manipulating the ACK flag in TCP packets. On the receiver side, the incoming packets are sniffed, and the ACK flag is interpreted to reconstruct the binary message. Using the same secret and modular arithmetic, the receiver decodes the transmitted bytes and reassembles the original message. The implementation ensures efficient transmission, a robust stop mechanism upon receiving a termination character, and precise packet filtering to maintain stealth and accuracy.

# Encryption

We have used 2 stage of encryption to provide a more robust covert channel.
1) We have divided 128 bit into 16 bytes, and in each byte XOR'ed the byte value with a secret number.
2) Then we divided the XOR'ed number by 8 and saved the modulo to least-significant 3 bits and quotient to most-significant 5 bits.
3) In this way, we can store every number that a byte can represent ( since with 5 bits we can represent 31 and with 3 bits we can represent 7 -> 31*8+7=255 )
4) Lastly, using ack field we send the encrypted byte bit-by-bit

# Decryption

In receiver side we have sniffed the incoming packets, and for every 8 packet we formed a byte from ACK field.
Since our whole encryption logic is irreversible, first we found the XOR'ed number before division using 5-bit quotient
and 3 bit modulo (number = quotient * 8 + modulo) and XOR'ed that number to obtain actual byte value before encryption.


# Covert Channel Capacity

We have tried several times our covert channel and we have obtained a capacity value around ~39-49 bits/sec