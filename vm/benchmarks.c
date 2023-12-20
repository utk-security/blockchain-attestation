#include <avr/io.h>
#include <stdint.h>
#include <assert.h>

#include <avr/pgmspace.h>


void  crc()
{
	// Initialize the CRC value to 0xFFFFFFFF
	
	uint32_t crc_value = 0xFFFFFFFF;
	uint16_t value = 100;

	// Calculate the CRC value
	crc_value = crc_value ^ value;
	for (int i = 0; i < 32; i++)
	{
		if (crc_value & 1)
		{
			crc_value = (crc_value >> 1) ^ 0xEDB88320;
		}
		else
		{
			crc_value = crc_value >> 1;
		}
	}

	// Return the CRC value
	return ;
}

 
//#define VM_UN_SET

int a[] = {4, 65, 5, 3, 9};

int b[] = {10, 20, 30, 40, 50, 60};

//void  __attribute__((section(".mysection"))) bubble_sort () {
void  bubble_sort(){
	
	#ifdef VM_UN_SET
	
	asm volatile("ldi r16, 1"
	"\n\t");
	asm volatile("ldi r17, 2"
	"\n\t");
	asm volatile("ldi r18, 3"
	"\n\t");
	asm volatile("ldi r19, 4"
	"\n\t");
	asm volatile("ldi r20, 5"
	"\n\t");
	asm volatile("ldi r21, 6"
	"\n\t");
	asm volatile("ldi r22, 7"
	"\n\t");
	asm volatile("ldi r23, 8"
	"\n\t");
	asm volatile("ldi r24, 9"
	"\n\t");
	asm volatile("ldi r25, 10"
	"\n\t");
	asm volatile("ldi r26, 11"
	"\n\t");
	asm volatile("ldi r27, 12"
	"\n\t");
	//r28 and r29 for stack pointer with space above
	asm volatile("ldi r30, 15"
	"\n\t");
	asm volatile("ldi r31, 16"
	"\n\t");
	
	#endif
	
	
	int i, t, j = 5, s = 1;
	while (s) {
		s = 0;
		for (i = 1; i < j; i++) {
			if (a[i] < a[i - 1]) {
				t = a[i];
				a[i] = a[i - 1];
				a[i - 1] = t;
				s = 1;
			}
		}
		j--;
	}
	
	//int i;
	//for (i=0;i<6;i++)
	//b[i] ++;
	
}


typedef unsigned short UInt16;
const UInt16 m1[3][4] = {
	{ 0x01, 0x02, 0x03, 0x04},
	{ 0x05, 0x06, 0x07, 0x08},
	{ 0x09, 0x0A, 0x0B, 0x0C}
};
const UInt16 m2[3][4] = {
	{ 0x01, 0x02, 0x03, 0x04},
	{ 0x06, 0x07, 0x08, 0x09},
	{ 0x0B, 0x0C, 0x0D, 0x0E}
	 
};

int m, n, p;
volatile UInt16 m3[3][4];

void   test_matrix(void) {
	

	for (m = 0; m < 3; m++) {
		 
			for (n = 0; n < 4; n++) {
				m3[m][n] += m1[m][n] + m2[m][n];
			}
		
	}
	
}


#define MOTION_DEPTH  20  // 60sec ?
unsigned int motMeasured[MOTION_DEPTH];
unsigned int motPtr;
unsigned int motNow;  // ++ for each motion detected (on or off, either count)
unsigned int motAverage;
unsigned int wdt_count;
#define WDT_COUNT_MAX 3   // 3 seconds





void   testMotion()
{
	int i;
	unsigned long sum = 0;
	for ( i=0; i<MOTION_DEPTH;i++)
	motMeasured[i] = 0;
	motPtr = 0;
	motNow = 0;
	motAverage = 0;
	wdt_count = 0;
	

	for (i=0; i<MOTION_DEPTH;i++)
	sum += motMeasured[i];


	if (sum > 20) // 20=0.33 * ( 20 * 3)
	sum <<= 3;
}


volatile char str[] = "password_real";
volatile char str2[] = "password_test";
 

void  __attribute__((section(".mysection"))) test_random2(void)
{
	char *p = str;
	char *q = str2;
	 
	int i;
	for (i=0;i<10;i++)
   {
	    while (*p)
	    {
		    // if characters differ, or end of the second string is reached
		    if (*p != *q) {
			    break;
		    }
		    
		    // move to the next pair of characters
		    p++;
		    q++;
	    } 	
	     
   }
}


uint32_t random_state_32 = 1234;
 
 void  test_random(void)
 {
	 int i=0;
	 
	 
	 for (i=0;i<10;i++)
	 {
		 uint32_t result = random_state_32;
		 
		 result ^= result << 13;
		 result ^= result >> 17;
		 result ^= result << 5;
		 random_state_32 = result;
		 
	 }
 }

