# Simple-MD5-Implementation-in-C:
The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value.One basic requirement of any cryptographic hash function is that it should be computationally infeasible to find two distinct messages that hash to the same value. MD5 fails this requirement catastrophically; such collisions can be found in seconds on an ordinary home computer.
Despite all this, MD5 continues to be widely used.
# Explanation:
MD5 processes a variable-length message into a fixed-length output of 128 bits. The input message is broken up into 512-bit blocks (sixteen 32-bit words)-
the message is then padded so that its length is divisible by 512.
The padding works as follows: first a single bit, 1, is appended to the end of the message. This is followed by as many zeros as are required to bring the length of the message up to 64 bits fewer than a multiple of 512. The remaining bits are filled up with 64 bits representing the length of the original message, modulo 2^64.

512-64=448. Remaining bits are filled with 64 bits.
448+64=512.

The main MD5 algorithm operates on a 128-bit state, divided into four 32-bit words, denoted A, B, C, and D. These are initialized to certain fixed constants. The main algorithm then uses each 512-bit message block in turn to modify the state. The processing of a message block consists of four similar stages, termed rounds; each round is composed of 16 similar operations based on a non-linear function F, modular addition, and left rotation.There are four possible functions; a different one is used in each round:

F(B,C,D) = (B and C) or (NOT(B) and D)
G(B,C,D) = (B and D) or (C and NOT(D))
H(B,C,D) =  B XOR C XOR D 
I(B,C,D) = C XOR (B or NOT(D))

The constant is stored in K[i] by equating it to (2 ** 32 * fabs(sin(i+1)). Here 0<=i<64. 

There are pre-initialised values of the shift amount for each buffer and operation.
rots[ 0..15] := { 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22 }
rots[16..31] := { 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20 }
rots[32..47] := { 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23 }
rots[48..63] := { 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 }

After initialising the buffer, the algorithm is performed which is explained in the code.
static Digest h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };

After each operation, the output of from that operation servers as the input for the next operation.
Likewise, these operations are performed on buffer 0xEFCDAB89, 0x98BADCFE and 0x10325476 whose results are then modulo added to give us the required 128-bit message digest.

The 128-bit (16-byte) MD5 hashes (also termed message digests) are typically represented as a sequence of 32 hexadecimal digits.
