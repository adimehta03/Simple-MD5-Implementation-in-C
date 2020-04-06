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
#include <stdlib.h>//standard library to access functions of dynamic memory allocations like malloc, realloc, calloc and free
#include <stdio.h>//standard input output scanf printf
#include <string.h>//to access string related functions like strlen
#include <math.h>//to use math related functions like fabs, sin, etc.
//UNIONS ARE USED IN ORDER TO ALLOCATE THE SAME MEMORY SHARED BY THE MEMBERS OF THE UNION WBunion.
//If we use structures, then it allocates memory to each member, which implies that we will have to dynamically allocate memory to each
//member which will complicate it. Thats why we arent using structures.
typedef union uwb {
    unsigned w;
    unsigned char b[4];//stores and print the message digest
} WBunion;
//typedef is basically userdefined datatype. In this case the userdefined datatype is WBunion.
//example- int w; similarly WBunion w;
//Without typedef we would have to create an object for the union uwb and then use "." to access the members of the union.

typedef unsigned Digest[4];//to store the output from each buffers final output. Digest[0] store A's output. Digest[1] stores B's output and so on.
 
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
//performs the algorithm of md5
unsigned *md5( const char *msg, int mlen) 
{
    //static is used to store the variable in the statically allocated memory instead of the automatically allocated memory.
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
    Digest abcd;//Non-linear functions
    DgstFctn fctn;//object of DgstFctn
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
    h[q] = h0[q];  //initialize the hash value for each loop respectively h[q] is equivalent to abcd[q]
 
    {
        grps  = 1 + (mlen+8)/64;//padding the message in order to make the length divisible by 512 bits. That's why dividing by 64 bits = 448 bits
        msg2 = malloc( 64*grps);//malloc dynamically allocates continous memory address.//calloc dynamically allocates non continous memory address.
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
        os += 64;//indicating all 64 operations are done.
    }
 
    if( msg2 )
        free( msg2 );//freeing the memory allocated to *msg2.
 
    return h;//returning the hash/message digest.
}    
 
int main( int argc, char *argv[] )
{
    start:
    {
        int n,j,k;
        char msg[30]; // store the string
        printf("How many strings do you wish to encrypt, max being 10?\n");
        scanf("%d",&n);//number of strings
        if(n>=1 && n<=10)//checking if n is 1<=n<=10
        {
            for(int i = 1; i <= n; i++){//intake the strings from the [user]
            printf("Please enter string %d which you wish to encrypt:\n",i); //format specifier %d = integers
            scanf("%s",msg);
            msg[strlen(msg)];//reassigning the length of the array based on the length of the string.
            unsigned *d = md5(msg, strlen(msg));//assigning the return value of function call md5 to d.
            WBunion u;
            printf("The hash for the given string is ");
            printf("= 0x");//2 for loops to concatenate the output of all the 4 buffers.
            for (j=0;j<4; j++){
                u.w = d[j];
                for (k=0;k<4;k++) printf("%02x",u.b[k]);
            }
            printf("\n");
            }
        }
        else//if not a number between 1 to 10
        {
            printf("Please try again\n");
            goto start;//goto can be accessed only in the function where it is defined
        }
    
    }
    return 0;
}
