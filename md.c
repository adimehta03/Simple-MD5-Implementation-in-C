/*
MIT License
Copyright (c) 2020 Aditya Mehta
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

//This is a quick and simple AES Encryption implementation using C Programming Language
//The below code takes in a Base64 encoded string(message) and and Base64 encoded Key from the 
//user and encrypts it according to AES algorithms and standards.
//As of now only 128 - bit level encryption is supported.

/*
  WARNING : THIS IMPLEMENTATION MUST NOT BE USED TO ENCRYPT AND DECRYPT TEXT,FILES OR ANYTHING
            AS IT IS VULNERABLE TO CACHE ATTACKS AND MANY OTHER ATTACKS.
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
//UNIONS ARE USED IN ORDER TO ALLOCATE THE SAME MEMORY SHARED BY THE MEMBERS OF THE UNION WBunion.
typedef union uwb {
    unsigned w;
    unsigned char b[4];
} WBunion;
 
typedef unsigned Digest[4];
 
unsigned f0( unsigned abcd[] ){
    return ( abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);} //f0 is a non-linear function F which is the first round consisting of 16 operations of modulo addition and left rotation
 
unsigned f1( unsigned abcd[] ){
    return ( abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);}//Similarly,f1 is also function which performs the operation (D AND B) OR (Negation NOT(D) AND C)
 
unsigned f2( unsigned abcd[] ){
    return  abcd[1] ^ abcd[2] ^ abcd[3];}//B XOR C XOR D
 
unsigned f3( unsigned abcd[] ){
    return abcd[2] ^ (abcd[1] |~ abcd[3]);}//C XOR (B OR NEGATION-NOT(D))
 
typedef unsigned (*DgstFctn)(unsigned a[]);
//Basically this function stores the constant of K[0],K[1],...,K[63] based on the equation K[i]=fabs(2**32 * sin(i+1))
unsigned *calcKs( unsigned *k)
{
    double s, pwr;
    int i;
 
    pwr = pow( 2, 32);
    for (i=0; i<64; i++) {
        s = fabs(sin(1+i));//in radians
        k[i] = (unsigned)( s * pwr );
    }
    return k;
}
 
// Rotate s Left by amt bits
unsigned rol( unsigned s, short amt )
{
    unsigned  msk1 = (1<<amt) -1;
    return ((s>>(32-amt)) & msk1) | ((s<<amt) & ~msk1);
}
 
unsigned *md5( const char *msg, int mlen) 
{
    static Digest h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };//Each element is a buffer A,B,C and D respectively.
//    static Digest h0 = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    static DgstFctn ff[] = { &f0, &f1, &f2, &f3 };//Stores the message digest of each block
    static short M[] = { 1, 5, 3, 7 };
    static short O[] = { 0, 1, 5, 0 };
    static short rot0[] = { 7,12,17,22};
    static short rot1[] = { 5, 9,14,20};
    static short rot2[] = { 4,11,16,23};
    static short rot3[] = { 6,10,15,21};
    static short *rots[] = {rot0, rot1, rot2, rot3 };//rots specifies the per-round shift amounts (short amt)
    static unsigned kspace[64];
    static unsigned *k;
 
    static Digest h;
    Digest abcd;//Non-linear functions
    DgstFctn fctn;
    short m, o, g;
    unsigned f;
    short *rotn;
    union {
        unsigned w[16]; // 16 operations
        char     b[64]; // 16 operations for 4 blocks =16*4=64 bit characters
    }mm;
    int os = 0;
    int grp, grps, q, p;
    unsigned char *msg2;
 
    if (k==NULL) k= calcKs(kspace);
 
    for (q=0; q<4; q++) // initialize the md5 for each block A,B,C and D...0,1,2 and 3
    h[q] = h0[q];  //initialize the hash value for each loop respectively 
 
    {
        grps  = 1 + (mlen+8)/64;// Pre-processing: adding a single 1 bit
        msg2 = malloc( 64*grps);
        memcpy( msg2, msg, mlen);
        msg2[mlen] = (unsigned char)0x80;  
        q = mlen + 1;
        while (q < 64*grps){ msg2[q] = 0; q++ ; }
        {
//            unsigned char t;
            WBunion u;
            u.w = 8*mlen;
//            t = u.b[0]; u.b[0] = u.b[3]; u.b[3] = t;
//            t = u.b[1]; u.b[1] = u.b[2]; u.b[2] = t;
            q -= 8;
            memcpy(msg2+q, &u.w, 4 );
        }
    }
 
    for (grp=0; grp<grps; grp++)
    {
        memcpy( mm.b, msg2+os, 64);
        for(q=0;q<4;q++) abcd[q] = h[q];
        for (p = 0; p<4; p++) {
            fctn = ff[p];
            rotn = rots[p];
            m = M[p]; o= O[p];
            for (q=0; q<16; q++) {
                g = (m*q + o) % 16;//performing 16 different operations on the same buffer which is then passed to the rol(v,amt) function.
                f = abcd[1] + rol( abcd[0]+ fctn(abcd) + k[q+16*p] + mm.w[g], rotn[q%4]);
 
                abcd[0] = abcd[3];
                abcd[3] = abcd[2];
                abcd[2] = abcd[1];
                abcd[1] = f;//makling the output of the first buffer as the input of the next buffer and left rotating 
            }
        }
        for (p=0; p<4; p++) // Add this loop's hash to result so far
            h[p] += abcd[p];
        os += 64;
    }
 
    if( msg2 )
        free( msg2 );
 
    return h;
}    
 
int main( int argc, char *argv[] )
{
    int j,k;
    char msg[30];
    printf("Please enter the string you wish to encrypt:\n");
    scanf("%s",msg);
    msg[strlen(msg)];
    unsigned *d = md5(msg, strlen(msg));
    WBunion u;
    printf("The hash for the given string is ");
    printf("= 0x");
    for (j=0;j<4; j++){
        u.w = d[j];
        for (k=0;k<4;k++) printf("%02x",u.b[k]);
    }
    printf("\n");
 
    return 0;
}