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
//If we use structures, then it allocates memory to each member, which implies that we will have to dynamically allocate memory to each
//member which will complicate it. Thats why we arent using structures.
typedef union uwb {
    unsigned w;
    unsigned char b[4];
} WBunion;

typedef unsigned Digest[4];

unsigned f0( unsigned abcd[] ){
    return ( abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);} 
 
unsigned f1( unsigned abcd[] ){
    return ( abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);}

unsigned f2( unsigned abcd[] ){
    return  abcd[1] ^ abcd[2] ^ abcd[3];}
 
unsigned f3( unsigned abcd[] ){
    return abcd[2] ^ (abcd[1] |~ abcd[3]);}
 
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
//performs the algorithm of md5
unsigned *md5( const char *msg, int mlen) 
{
  
    static Digest h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };//Each element is a buffer A,B,C and D respectively.
    static DgstFctn ff[] = { &f0, &f1, &f2, &f3 };//Stores the message digest of each block
    static short M[] = { 1, 5, 3, 7 };
    static short O[] = { 0, 1, 5, 0 };
    //Following are pre-initialised values of the shift amount for each buffer and operation.
    static short rot0[] = { 7,12,17,22};
    static short rot1[] = { 5, 9,14,20};
    static short rot2[] = { 4,11,16,23};
    static short rot3[] = { 6,10,15,21};
    static short *rots[] = {rot0, rot1, rot2, rot3 };//rots specifies the per-round shift amounts (short amt)
    static unsigned kspace[64];
    static unsigned *k;
    static Digest h;
    Digest abcd;
    DgstFctn fctn;
    short m, o, g;
    unsigned f;
    short *rotn;
    union {
        unsigned w[16]; 
        char     b[64]; 
    }mm;
    int os = 0;
    int grp, grps, q, p;
    unsigned char *msg2;
 
    if (k==NULL) k= calcKs(kspace);
 
    for (q=0; q<4; q++) 
    h[q] = h0[q];  
 
    {
        grps  = 1 + (mlen+8)/64;//padding the message in order to make the length divisible by 512 bits. That's why dividing by 64 bits = 448 bits
        msg2 = malloc( 64*grps);
        memcpy( msg2, msg, mlen);// Copies "mlen" bytes from address "msg" to address "msg2"
        msg2[mlen] = (unsigned char)0x80;//hexa decimal of 80 in binary is 1 bit. So storing the 1 bit in the final index of the array.
        q = mlen + 1;
        while (q < 64*grps){ msg2[q] = 0; q++ ; }
        {
            WBunion u;
            u.w = 8*mlen;//the length of the data is equal to 8 bits * length of the message
            q -= 8;//based on the length subtract 8 bits.
            memcpy(msg2+q, &u.w, 4 );//appending the remaining bits to the message in order to make it 512 bits again.
        }
    }
    //Processing the blocks.
    for (grp=0; grp<grps; grp++)
    {
        memcpy( mm.b, msg2+os, 64);
        for(q=0;q<4;q++) abcd[q] = h[q]; //assigning the appended and pre-processed digest to abcd[0],abcd[1],abcd[2] and abcd[3].      
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
 
    return h;//returning the hash/message digest.
}    
 
int main( int argc, char *argv[] )
{
    start:
    {
        int n,j,k;
        char msg[30]; 
        printf("How many strings do you wish to encrypt, max being 10?\n");
        scanf("%d",&n);
        if(n>=1 && n<=10)
        {
            for(int i = 1; i <= n; i++){
            printf("Please enter string %d which you wish to encrypt:\n",i); 
            scanf("%s",msg);
            msg[strlen(msg)];
            unsigned *d = md5(msg, strlen(msg));
            WBunion u;
            printf("The hash for the given string is ");
            printf("= 0x");/
            for (j=0;j<4; j++){
                u.w = d[j];
                for (k=0;k<4;k++) printf("%02x",u.b[k]);
            }
            printf("\n");
            }
        }
        else
        {
            printf("Please try again\n");
            goto start;//goto can be accessed only in the function where it is defined
        }
    
    }
    return 0;
}
