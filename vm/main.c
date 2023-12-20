/*
This is the source code release 0.1 for the paper Blockchain-based Runtime Attestation against Physical Fault Injection Attacks on Edge Devices in IEEE/ACM SEC 2023
*/

#include <avr/io.h>
#include <stdint.h>
#include <assert.h>

#include <avr/pgmspace.h>
 
typedef int bool;

#define endian_switch 1

#define true 1
#define false 0
 
#define ENTRY_ADDRESS 0x0
#define ATMEGA2560_RAMPZ 0x58
#define IO_REG_START 0x20

// Globals 
#define CLR 0
#define SET 1
#define IGNORE 2

uint16_t result;
int stop_fetch = 0;

int32_t fetch();
#define SPH_ADDRESS 0x5E
#define SPL_ADDRESS 0x5D
#define FLASH_SIZE 4096
 
uint32_t inst_check()
{
	
	//init
	
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
	asm volatile("ldi r28, 13"
	"\n\t");
	asm volatile("ldi r29, 14"
	"\n\t");
	asm volatile("ldi r30, 15"
	"\n\t");
	asm volatile("ldi r31, 16"
	"\n\t");
	
	#endif
	// ADC instruction
	 

	asm volatile("adc r16, r18"
	"\n\t");
	
	
	// ADD instruction
	 

	asm volatile("add r12, r14"
	"\n\t");
	
	
	// ADDIW instruction
	
	asm volatile("adiw 24,1"
	"\n\t");
	
	
	
	// AND instruction
	

	asm volatile("and r16, r18"
	"\n\t"
	);


	
	// ANDI instruction
	 

	asm volatile("andi r16, 16"
	"\n\t" );



	// ASR instruction
	 

	asm volatile("asr r16"
	"\n\t"
	"asr r18"
	"\n\t"
	"asr r20"
	"\n\t"
	);

	//bld 
	asm volatile("bld r0,4"
	"\n\t");
	
	//brcc
	 

	asm volatile (
	"brcc label" "\n\t"
	);
		 
	
	asm volatile("add r16, r18"
	"\n\t");	
	
	asm volatile("label: sub r16, r18"
	"\n\t");
	
	
	//brcs
	asm volatile (
	"brcs label2" "\n\t"
	);
	
	
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label2: sub r16, r18"
	"\n\t");
	
	//breq
	
	asm volatile("cp r10, r12""\n\t"
				 "breq label_breq" "\n\t"
				 );
	
	
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_breq: sub r16, r18"
	"\n\t");
				 
		
	//brge
	asm volatile("cp r10, r12""\n\t"
				"brge label_brge" "\n\t"
				);
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_brge: sub r16, r18"
	"\n\t");
	
	
	
	
	//brlt
	asm volatile("cp r10, r12""\n\t"
	"brlt label_brlt" "\n\t"
	);
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_brlt: sub r16, r18"
	"\n\t");
	
	
	
	
	
	//brmi
	asm volatile("subi r18, 4""\n\t"
	"brmi label_brmi" "\n\t"
	);
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_brmi: sub r16, r18"
	"\n\t");
	
	
	
	//brne
	asm volatile("cpi r27,5""\n\t"
	"brne label_brne" "\n\t"
	);
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_brne: sub r16, r18"
	"\n\t");
	
	//brpl
	asm volatile("subi r27,50""\n\t"
	"brpl label_brpl" "\n\t"
	);
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_brpl: sub r16, r18"
	"\n\t");
	
	//brtc
	asm volatile("brtc label_brtc""\n\t"
	);
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_brtc: sub r16, r18"
	"\n\t");
	
	//brts
	asm volatile("brts label_brts""\n\t"
	);
	
	asm volatile("add r16, r18"
	"\n\t");
	
	asm volatile("label_brts: sub r16, r18"
	"\n\t");
	
	//bst r1,2 
	asm volatile("bst r1,2""\n\t"
	);
	 
	// CLI instruction
	asm volatile("cli"
	"\n\t");
	
	
	
	// CLT instruction

	asm volatile("clt"
	"\n\t");
	
	
	// COM instruction
	

	asm volatile("com r16"
	"\n\t"
	"com r18"
	"\n\t"
	"com r20"
	"\n\t"
	);
	
	
	// CPC instruction
	#define MY_PARAMETER 0x01

	asm volatile("cpc r16, r18"
	"\n\t"
	);

	
	// CPI instruction
	#define MY_PARAMETER 0x01

	asm volatile("cpi r16, 3"
	"\n\t" );


	

	// CPSE instruction
	 

	asm volatile("cpse r16, r18"
	"\n\t"
	);
	
	
	// DEC instruction
	#define MY_PARAMETER 0x01

	asm volatile("dec r16"
	"\n\t"
	"dec r18"
	"\n\t"
	"dec r20"
	"\n\t"
	);
	
	
	// EOR instruction
	#define MY_PARAMETER 0x01

	asm volatile("eor r16, r18"
	"\n\t"
	);
	
	
	// INC instruction
	#define MY_PARAMETER 0x01

	asm volatile("inc r16"
	"\n\t"
	"inc r18"
	"\n\t"
	"inc r20"
	"\n\t"
	);

	
	// LD instruction
	#define MY_PARAMETER 0x01

	asm volatile("ld r16, X"
	"\n\t"
	"ld r16, Y"
	"\n\t"
	"ld r16, Z"
	"\n\t");
	
	//ldi instruction
	
	asm volatile("ldi r24, 10"
	"\n\t");
	
	//lds instruction
	
	asm volatile("lds r24, 200"
	"\n\t");
	
	
	// LSR instruction
	#define MY_PARAMETER 0x01

	asm volatile("lsr r16"
	"\n\t"
	"lsr r18"
	"\n\t"
	"lsr r20"
	"\n\t"
	);



	
	
	// MOV instruction
	#define MY_PARAMETER 0x01

	asm volatile("mov r16, r18"
	"\n\t"
	);
	
	
	
	// MOVW instruction
	#define MY_PARAMETER 0x1234

	asm volatile("movw r16, r18"
	"\n\t");
	
	
	// MUL related  instruction
	#define MY_PARAMETER 0x12

	asm volatile("mulsu r16, r18"
	"\n\t"
	"muls r20, r16"
	"\n\t"
	"mul r20, r16"
	"\n\t");
	
	
	// NOP instruction
	
	asm volatile("nop"
				 "\n\t");
 


	
	// NEG instruction
	#define MY_PARAMETER 0x01

	asm volatile("neg r16"
	"\n\t"
	"neg r18"
	"\n\t"
	"neg r20"
	"\n\t"
	);
	
	
	

	// OR instruction
	#define MY_PARAMETER 0x01

	asm volatile("or r16, r18"
	"\n\t"
	);


	// ORI instruction
	#define MY_PARAMETER 0x01

		asm volatile("ori r16, 20"
					 "\n\t" );
	
	 

	//	truction
	#define MY_PARAMETER 0x01

	asm volatile("push r16"
	"\n\t"
	"push r18"
	"\n\t"
	"push r20"
	"\n\t"
	); 
	

	// ROR instruction
	#define MY_PARAMETER 0x01

	asm volatile("ror r16"
	"\n\t"
	"ror r18"
	"\n\t"
	"ror r20"
	"\n\t"
	);
	
	
	// SBC instruction
	#define MY_PARAMETER 0x01

	asm volatile("sbc r16, r18"
	"\n\t"
	);
	
	
	

	// SBCI instruction
	#define MY_PARAMETER 0x01

	asm volatile("sbci r16, %0"
	"\n\t" ::"M"(MY_PARAMETER));
	
	// SBIW instruction
	#define MY_PARAMETER 0x01

	asm volatile("sbiw r24, 1"
	"\n\t" );
	
	
	// SBRC and SBRS instruction
	#define MY_PARAMETER 0x01

	asm volatile("sub r0,r1" "\n\t"
				"sbrc r0,7" "\n\t"
				"sub r0,r1" "\n\t"
				"nop" "\n\t"	
	 );
	 
	 asm volatile("sub r0,r1" "\n\t"
	 "sbrs r0,7" "\n\t"
	 "sub r0,r1" "\n\t"
	 "nop" "\n\t"
	 );
	
	
	// SEC instruction
	#define MY_PARAMETER 0x01

	asm volatile("sec"
	"\n\t");
	
	
	

	// SEI instruction
	#define MY_PARAMETER 0x01

	asm volatile("sei"
	"\n\t");

	// SEt instruction
	#define MY_PARAMETER 0x01

	asm volatile("set"
	"\n\t");

	

	// ST instruction
	#define MY_PARAMETER 0x01

	asm volatile("st X, r16"
	"\n\t"
	"st Y, r16"
	"\n\t"
	"st Z, r16"
	"\n\t");


	// STS instruction
	#define MY_PARAMETER 0x01

	asm volatile("sts 200, r16"
	"\n\t"
	"sts 202, r18"
	"\n\t");
	 

 

// SUB instruction
#define MY_PARAMETER 0x01

	asm volatile("sub r16, r18"
				 "\n\t"
				 );


// SUBI instruction
#define MY_PARAMETER 0x01

	asm volatile("subi r16, %0"
				 "\n\t" ::"M"(MY_PARAMETER));






// SWAP instruction
#define MY_PARAMETER 0x01

	asm volatile("swap r16"
				 "\n\t"
				 "swap r18"
				 "\n\t"
				 "swap r20"
				 "\n\t"
				 );





}

#define FLASH_ADDRESS 0x15554
#define BUFFER_SIZE 1024

void read_flash_code(uint8_t *buffer)
{
	//THE +8 is used here to skip the beginnig of the code.hack. 
	
	//memcpy_PF(buffer, FLASH_ADDRESS+12, BUFFER_SIZE);
	memcpy_PF(buffer, FLASH_ADDRESS, BUFFER_SIZE);
}


uint8_t code_buffer[256];

struct status
{

	int8_t I : 3;
	int8_t T : 3;
	int8_t H : 3;
	int8_t S : 3;
	int8_t V : 3;
	int8_t N : 3;
	int8_t Z : 3;
	int8_t C : 3;
};

struct status newStatus;
void clear_status(struct status *p)
{
	p->C = IGNORE;
	p->Z = IGNORE;
	p->N = IGNORE;
	p->V = IGNORE;
	p->S = IGNORE;
	p->H = IGNORE;
	p->T = IGNORE;
	p->I = IGNORE;
}
void zero_status(struct status *p)
{
	p->C = CLR;
	p->Z = CLR;
	p->N = CLR;
	p->V = CLR;
	p->S = CLR;
	p->H = CLR;
	p->T = CLR;
	p->I = CLR;
}

//IN another program the S and N are set.


void specific_status(struct status *p)
{
	 
	p->Z = SET;
	 
	//p->S = SET;
	 
}



uint8_t memory[FLASH_SIZE];

int memory_flipped[FLASH_SIZE];

#define RAMSIZE 0x4200

uint8_t ram[RAMSIZE];

int32_t programStart = ENTRY_ADDRESS;
uint16_t PC;

int32_t totalinstructions;
int32_t totalcycles;

uint32_t block_chain_result = 0; 

int32_t trackedFetches = 0;
int32_t fetchN(int32_t n)
{
	bool success = true;
	bool timed = false;
	 
	// while (success && n)
	{
		success = fetch();
		// n--;
	}

	return success;
}

struct status SREG_status;
void pushStatus(struct status *newStatus)
{
	if (newStatus->C != IGNORE)
	{
		SREG_status.C = newStatus->C;
	}
	if (newStatus->Z != IGNORE)
	{
		SREG_status.Z = newStatus->Z;
	}
	if (newStatus->N != IGNORE)
	{
		SREG_status.N = newStatus->N;
	}
	if (newStatus->V != IGNORE)
	{
		SREG_status.V = newStatus->V;
	}
	if (newStatus->S != IGNORE)
	{
		SREG_status.S = newStatus->S;
	}
	if (newStatus->H != IGNORE)
	{
		SREG_status.H = newStatus->H;
	}
	if (newStatus->T != IGNORE)
	{
		SREG_status.T = newStatus->T;
	}
	if (newStatus->I != IGNORE)
	{
		SREG_status.I = newStatus->I;
	}
}

void engineInit()
{
	int32_t SPREG;
	int i;
	
	for (i=0;i<FLASH_SIZE;i++)
	 memory_flipped[i] =0; 
	 
	zero_status(&SREG_status);
	specific_status(&SREG_status);

	PC = programStart;
	
	 
}

int32_t getValueFromHex(uint8_t *buffer, int32_t size)
{
	int32_t value = 0;
	int32_t cursor = 0;
	while (size--)
	{
		int32_t shift = (1 << size * 4);
		if (buffer[cursor] < ':')
		{
			value += (buffer[cursor++] - '0') * shift;
		}
		else
		{
			value += (buffer[cursor++] - 0x37) * shift;
		}
	}

	return value;
}

void loadProgram(uint8_t *binary);
void loadDefaultProgram();
void execProgram();

uint8_t readMemory(int32_t address);
void writeMemory(int32_t address, int32_t value);
void pushStatus(struct status *newStatus);
void decrementStackPointer();

void loadDefaultProgram()
{

	// ac:   11 24           eor     r1, r1
	memory[0x00] = 0x24;
	memory[0x01] = 0x11;
	// ae:   1f be           out     0x3f, r1        ; 63
	memory[0x02] = 0xBE;
	memory[0x03] = 0x1F;
	// b0:   cf ef           ldi     r28, 0xFF       ; 255
	// b2:   da e0           ldi     r29, 0x0A       ; 10
	memory[0x04] = 0xEF;
	memory[0x05] = 0xCF;
	memory[0x06] = 0xE0;
	memory[0x07] = 0xD2;
	// b4:   de bf           out     0x3e, r29       ; 62
	// b6:   cd bf           out     0x3d, r28       ; 61
	memory[0x08] = 0xBF;
	memory[0x09] = 0xDE;
	memory[0x0A] = 0xBF;
	memory[0x0B] = 0xCD;

	memory[0x0C] = 0xE0;
	memory[0x0D] = 0x21;
	memory[0x0E] = 0xE0;
	memory[0x0F] = 0xA0;

	memory[0x10] = 0xE0;
	memory[0x11] = 0x21;
	memory[0x12] = 0xE0;
	memory[0x13] = 0xA0;

	memory[0x14] = 0xE0;
	memory[0x15] = 0xB1;
	memory[0x16] = 0xC0;
	memory[0x17] = 0x01;

	// b8:   0e 94 62 00     call    0xc4    ; 0xc4 <main>
	memory[0x18] = 0x92;
	memory[0x19] = 0x1D;
	memory[0x1A] = 0x30;
	memory[0x1B] = 0xA2;
	// c4:   cf 93           push    r28
	// c6:   df 93           push    r29
	memory[0x20] = 0x07;
	memory[0x21] = 0xB2;
	memory[0x22] = 0xF7;
	memory[0x23] = 0xE1;

	memory[0x24] = 0xD0;
	memory[0x25] = 0x02;
	memory[0x26] = 0xC0;
	memory[0x27] = 0x0F;

	memory[0x28] = 0xCF;
	memory[0x29] = 0xD4;
	memory[0x2A] = 0x01;
	memory[0x2B] = 0x01;

	memory[0x2C] = 0x92;
	memory[0x2D] = 0x10;
	memory[0x2E] = 0x01;
	memory[0x2F] = 0x00;

	memory[0x30] = 0x92;
	memory[0x31] = 0x10;
	memory[0x32] = 0x01;
	memory[0x33] = 0x00;

	memory[0x34] = 0x91;
	memory[0x35] = 0x80;
	memory[0x36] = 0x01;
	memory[0x37] = 0x01;

	memory[0x38] = 0x91;
	memory[0x39] = 0x90;
	memory[0x3A] = 0x96;
	memory[0x3B] = 0x01;

	memory[0x3C] = 0x01;
	memory[0x3D] = 0x01;
	memory[0x3E] = 0x93;
	memory[0x3F] = 0x90;

	memory[0x40] = 0x01;
	memory[0x41] = 0x00;
	memory[0x42] = 0x93;
	memory[0x43] = 0x80;

	memory[0x44] = 0xCF;
	memory[0x45] = 0xF6;
	memory[0x46] = 0x94;
	memory[0x47] = 0xF8;

	memory[0x44] = 0xCF;
	memory[0x45] = 0xFF;
}

int32_t currentAddressCursor = ENTRY_ADDRESS;
void loadPartialProgram(uint8_t *binary)
{
	int32_t lineCursor = 0;
	assert(binary[lineCursor++] == ':');
	int32_t byteCount = getValueFromHex(&binary[lineCursor], 2);
	int32_t address = getValueFromHex(&binary[lineCursor += 2], 4);
	int32_t recordType = getValueFromHex(&binary[lineCursor += 4], 2);
	if (recordType == 0x00)
	{
		while (byteCount)
		{
			int32_t instr = getValueFromHex(&binary[lineCursor += 2], 2);
			memory[currentAddressCursor++] = getValueFromHex(&binary[lineCursor += 2], 2);
			memory[currentAddressCursor++] = instr;
			byteCount -= 2;
		}
	}
	else if (recordType == 0x01)
	{
		return;
	}
	else
	{
		assert(false);
	}
}

void loadProgram(uint8_t *binary)
{
	int32_t fileCursor = 0;
	int32_t addressCursor = ENTRY_ADDRESS;
	while (true)
	{
		assert(binary[fileCursor++] == ':');
		int32_t byteCount = getValueFromHex(&binary[fileCursor], 2);
		int32_t address = getValueFromHex(&binary[fileCursor += 2], 4);
		int32_t recordType = getValueFromHex(&binary[fileCursor += 4], 2);
		if (recordType == 0x00)
		{
			while (byteCount)
			{
				int32_t instr = getValueFromHex(&binary[fileCursor += 2], 2);
				memory[addressCursor++] = getValueFromHex(&binary[fileCursor += 2], 2);
				memory[addressCursor++] = instr;
				byteCount -= 2;
			}
			while (binary[++fileCursor] != ':')
				;
		}
		else if (recordType == 0x01)
		{
			break;
		}
		else if (recordType == 0x02)
		{
			int32_t segmentAddress = 0;
			while (byteCount)
			{
				segmentAddress = getValueFromHex(&binary[fileCursor += 2], 2);
				segmentAddress = segmentAddress << 4;
				segmentAddress |= getValueFromHex(&binary[fileCursor += 2], 2);
				segmentAddress = segmentAddress << 4;
				byteCount -= 2;
			}
			while (binary[++fileCursor] != ':')
				;
			addressCursor = segmentAddress * 16;
		}
		else
		{
			assert(false);
		}
	}
	free(binary);
}

int8_t generateVStatus(uint8_t firstOp, uint8_t secondOp)
{
	bool firstMSB = (firstOp & 0x80) > 0;
	bool secondMSB = (secondOp & 0x80) > 0;
	if (firstMSB && secondMSB)
	{
		return ((firstOp + secondOp) & 0x80) > 0 ? CLR : SET;
	}
	else if (!firstMSB && !secondMSB)
	{
		return ((firstOp + secondOp) & 0x80) == 0 ? CLR : SET;
	}

	return CLR;
}

int8_t generateVStatus2(uint8_t firstOp, uint8_t secondOp)
{
	bool firstMSB = (firstOp & 0x80) > 0;
	bool secondMSB = (secondOp & 0x80) > 0;
	if (firstMSB && !secondMSB)
	{
		return ((firstOp - secondOp) & 0x80) == 0 ? SET : CLR;
	}
	else if (!firstMSB && secondMSB)
	{
		return ((firstOp - secondOp) & 0x80) > 0 ? SET : CLR;
	}

	return CLR;
}

int8_t generateHStatus(uint8_t firstOp, uint8_t secondOp)
{
	return (((firstOp & 0xF) + (secondOp & 0xF)) & 0x10) == 0x10 ? SET : CLR;
}


int8_t generateHStatus_Neg(uint8_t op)
{
     uint8_t mask = 8; 
	 
	 uint8_t r = 0-op;
	 
 	 uint8_t b_op = (op & mask) >> 3;
 
 	 uint8_t b_r = (r & mask) >> 3;
 
	 
	 uint8_t temp = b_r | !b_op;
	 return temp; 
}


int8_t generateHStatus_Sub(uint8_t op1, uint8_t op2)
{
     uint8_t mask = 8; 
	uint8_t r = op1 - op2;
 	 uint8_t b_op1 = (op1 & mask) >> 3;
 
 	 uint8_t b_op2 = (op2 & mask )>> 3;
 
	 uint8_t b_r = (r & mask) >> 3;
 
	 
	 uint8_t temp = !b_op1 & b_op2 | b_op2 & b_r | b_r & !b_op1;
	 return temp; 
	

	 
}


void execProgram()
{
	stop_fetch = 0;
	while (fetch() && (stop_fetch == 0))
	{
	}
}

 
bool longOpcode(uint16_t programCounter)
{
	uint16_t opcode0 = memory[programCounter];
	uint16_t opcode1 = memory[programCounter + 1];

	switch (opcode0)
	{
	case 0x90:
	case 0x91:
		if ((opcode1 & 0xF) == 0) // lds
		{
			return true;
		}
		break;
	case 0x92:
	case 0x93:
		if ((opcode1 & 0xF) == 0) // sts
		{
			return true;
		}
		break;
	case 0x94:
	case 0x95:
		if ((opcode1 & 0xF) > 0xB) // jmp / call
		{
			return true;
		}
		break;
	}

	return false;
}

void incrementStackPointer()
{
	int32_t SPREG = (ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS];
	SPREG++;
	ram[SPH_ADDRESS] = (SPREG & 0xFF00) >> 8;
	ram[SPL_ADDRESS] = (SPREG & 0xFF);
}

void decrementStackPointer()
{
	int32_t SPREG = (ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS];
	SPREG--;
	ram[SPH_ADDRESS] = (SPREG & 0xFF00) >> 8;
	ram[SPL_ADDRESS] = (SPREG & 0xFF);
}

void handleUnimplemented()
{

	assert(0);
}

uint16_t result;
struct status newStatus;

void switch_higher_pc_content(int i, int j)
{
	int temp_pc_value;
	
	if (memory_flipped[i] == 0)
	{temp_pc_value = memory[i];
	memory[i] = memory[j];
	memory[j] = temp_pc_value;
	memory_flipped[i] = memory_flipped[j] = 1;
	}
}

uint32_t block_chain_calc(uint32_t prev, uint32_t data, uint32_t time) {
	uint32_t hash = prev;
	hash += data;
	hash += time;
	hash = hash * 0x5DEECE66DL + 0xBL;
	hash = (hash & 0xFFFFFFFF0000FFFF) | (hash >> 32);
	return hash;
}
int32_t fetch()
{
	int last;
	
	uint16_t result_old; 

	totalinstructions = totalinstructions + 1;

	totalcycles = totalcycles + 1;

	// if ((PC >= FLASH_SIZE) || ((memory[PC] == 0x95) && (memory[PC + 1] == 0x98))) //break
	// return false;

	// if (PC == 8480)
	//{
	// last = 1;
	//}

	result = 0;

	clear_status(&newStatus);

	// change the order of PC and PC+1
	int temp_pc_value;
	
	if ((endian_switch)&&(memory_flipped[PC]==0))
	{
		
		temp_pc_value = memory[PC];
		memory[PC] = memory[PC + 1];
		memory[PC + 1] = temp_pc_value;
		memory_flipped[PC]  = 1; 
		memory_flipped[PC+1]  = 1; 
	}
		
	 //block_chain_result = block_chain_calc(block_chain_result, (uint32_t)memory[PC], (uint32_t)totalinstructions);
	
	switch (memory[PC])
	{
	
	case 0x0:
		if (memory[PC + 1] == 0x00) // nop
		{
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0x1: // movw
		ram[((memory[PC + 1] & 0xF0) >> 4) * 2] = ram[(memory[PC + 1] & 0xF) * 2];
		ram[(((memory[PC + 1] & 0xF0) >> 4) * 2) + 1] = ram[((memory[PC + 1] & 0xF) * 2) + 1];
		// No SREG_status Updates
		PC += 2;
		break;
	case 0x2: // muls
	case 0x3: // mulsu
		result = (int)ram[((memory[PC + 1] & 0xF0) >> 4) * 2] * (int)ram[(memory[PC + 1] & 0xF) * 2];
		ram[0] = result & 0xFF;
		ram[1] = result >> 8;
		// No SREG_status Updates
		PC += 2;
		totalcycles++;
		break;
	case 0x4:
	case 0x5:
	case 0x6:
	case 0x7: // cpc
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] - ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		result -= SREG_status.C == SET ? 1 : 0;
		newStatus.H = generateHStatus_Sub(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)] +SREG_status.C == SET ? 1 : 0);
		newStatus.V = generateVStatus2(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)] + (SREG_status.C == SET ? 1 : 0));
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? newStatus.Z : CLR;
		newStatus.C = abs(ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)] + (SREG_status.C == SET ? 1 : 0)) > abs(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)]) ? SET : CLR;
		// Special Cases
		if (((ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] & 0x80) == 0) && ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)] == 0x7F && SREG_status.C == SET)
		{
			newStatus.V = CLR;
		}
		if (((ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] & 0x80) == 0x80) && ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)] == 0x7F && SREG_status.C == SET)
		{
			newStatus.V = SET;
		}
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x8:
	case 0x9:
	case 0xA:
	case 0xB: // sbc
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] - ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		result -= SREG_status.C == SET ? 1 : 0;
		newStatus.H = generateHStatus_Sub(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.V = generateVStatus2(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? newStatus.Z : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		newStatus.C = abs(ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)] + (SREG_status.C == SET ? 1 : 0)) > abs(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)]) ? SET : CLR;
		ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result & 0xFF;
		PC += 2;
		break;
	case 0xC:
	case 0xD:
	case 0xE:
	case 0xF: // add
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] + ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.H = generateHStatus(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.V = generateVStatus(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.C = result > 0xFF ? SET : CLR;
		ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result & 0xFF;
		PC += 2;
		break;
	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13: // cpse
		if (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] == ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)])
		{
			PC += 2;
			totalcycles++;
			if (longOpcode(PC))
			{
				PC += 2;
				totalcycles++;
			}
		}
		// No SREG_status Updates
		PC += 2;
		break;
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17: // cp
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] - ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.H = generateHStatus_Sub(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.V = generateVStatus2(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		newStatus.C = abs(ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]) > abs(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)]) ? SET : CLR;
		PC += 2;
		break;
	case 0x18:
	case 0x19:
	case 0x1A:
	case 0x1B: // sub
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] - ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.H = generateHStatus_Sub(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		//fixed bug here 
		newStatus.V = generateVStatus2(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.C = abs(ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]) > abs(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)]) ? SET : CLR;
		ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result & 0xFF;
		PC += 2;
		break;
	case 0x1C:
	case 0x1D:
	case 0x1E:
	case 0x1F: // adc
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] + ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		result += SREG_status.C == SET ? 1 : 0;
		newStatus.H = generateHStatus(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.V = generateVStatus(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)], ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		newStatus.C = result > 0xFF ? SET : CLR;
		ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result & 0xFF;
		PC += 2;
		break;
	case 0x20:
	case 0x21:
	case 0x22:
	case 0x23: // and
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] & ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
		newStatus.V = CLR;
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x24:
	case 0x25:
	case 0x26:
	case 0x27: // eor
		ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)] = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)] ^ ram[(((memory[PC] & 0x2) << 3) | (memory[PC + 1] & 0xF))];
		result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
		newStatus.V = CLR;
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x28:
	case 0x29:
	case 0x2A:
	case 0x2B: // or
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] | ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
		newStatus.V = CLR;
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x2C:
	case 0x2D:
	case 0x2E:
	case 0x2F: // mov
		ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)];
		PC += 2;
		break;
	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
	case 0x36:
	case 0x37:
	case 0x38:
	case 0x39:
	case 0x3A:
	case 0x3B:
	case 0x3C:
	case 0x3D:
	case 0x3E:
	case 0x3F: // cpi
		result = ram[16 + (memory[PC + 1] >> 4)] - (((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF));
		newStatus.V = generateVStatus2(ram[16 + (memory[PC + 1] >> 4)], (((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF)));
		newStatus.H = generateHStatus_Sub(ram[16 + (memory[PC + 1] >> 4)], (((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF)));
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		newStatus.C = abs((((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF))) > abs(ram[16 + (memory[PC + 1] >> 4)]) ? SET : CLR;
		PC += 2;
		break;
	case 0x40:
	case 0x41:
	case 0x42:
	case 0x43:
	case 0x44:
	case 0x45:
	case 0x46:
	case 0x47:
	case 0x48:
	case 0x49:
	case 0x4A:
	case 0x4B:
	case 0x4C:
	case 0x4D:
	case 0x4E:
	case 0x4F: // sbci
		result = ((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF);
		newStatus.H = generateHStatus_Sub(ram[16 + ((memory[PC + 1] & 0xF0) >> 4)], result);
		newStatus.V = generateVStatus2(ram[16 + ((memory[PC + 1] & 0xF0) >> 4)], result);
		result += SREG_status.C;
		newStatus.C = abs(result) > abs(ram[16 + ((memory[PC + 1] & 0xF0) >> 4)]) ? SET : CLR;
		ram[16 + ((memory[PC + 1] & 0xF0) >> 4)] -= result;
		result = ram[16 + ((memory[PC + 1] & 0xF0) >> 4)];
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? newStatus.Z : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x50:
	case 0x51:
	case 0x52:
	case 0x53:
	case 0x54:
	case 0x55:
	case 0x56:
	case 0x57:
	case 0x58:
	case 0x59:
	case 0x5A:
	case 0x5B:
	case 0x5C:
	case 0x5D:
	case 0x5E:
	case 0x5F: // subi
		result = ((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF);
		newStatus.H = generateHStatus_Sub(ram[16 + ((memory[PC + 1] & 0xF0) >> 4)], result);
		newStatus.V = generateVStatus(ram[16 + ((memory[PC + 1] & 0xF0) >> 4)], result);
		newStatus.C = abs(result) > abs(ram[16 + ((memory[PC + 1] & 0xF0) >> 4)]) ? SET : CLR;
		ram[16 + ((memory[PC + 1] & 0xF0) >> 4)] -= result;
		result = ram[16 + ((memory[PC + 1] & 0xF0) >> 4)];
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x60:
	case 0x61:
	case 0x62:
	case 0x63:
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
	case 0x68:
	case 0x69:
	case 0x6A:
	case 0x6B:
	case 0x6C:
	case 0x6D:
	case 0x6E:
	case 0x6F: // ori
		result = ((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF);
		ram[16 + ((memory[PC + 1] & 0xF0) >> 4)] |= result;
		result = ram[16 + ((memory[PC + 1] & 0xF0) >> 4)];
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.V = CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
	case 0x79:
	case 0x7A:
	case 0x7B:
	case 0x7C:
	case 0x7D:
	case 0x7E:
	case 0x7F: // andi
		result = ((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF);
		ram[16 + ((memory[PC + 1] & 0xF0) >> 4)] &= result;
		newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
		newStatus.Z = result == 0x00 ? SET : CLR;
		newStatus.V = CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		PC += 2;
		break;
	case 0x80:
	case 0x81:
		if ((memory[PC + 1] & 0xF) >= 0x8) // ld (ldd) y
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) < 0x8) // ld (ldd) z
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0x82:
	case 0x83:
		if ((memory[PC + 1] & 0xF) >= 0x8) // st (std) y
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) < 0x8) // st (std) z
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		handleUnimplemented();
	case 0x84:
	case 0x85:
	case 0x8C:
	case 0x8D:
		if ((memory[PC + 1] & 0xF) >= 0x8) // ld (ldd) y
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) < 0x8) // ld (ldd) z
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0x86:
	case 0x87:
		if ((memory[PC + 1] & 0xF) >= 0x8) // st (std) y
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) < 0x8) // st (std) z
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		handleUnimplemented();
	case 0x88:
	case 0x89:
		if ((memory[PC + 1] & 0xF) >= 0x8) // ld (ldd) y
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) < 0x8) // ld (ldd) z
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0x8A:
	case 0x8B:
	case 0x8E:
	case 0x8F:
		if ((memory[PC + 1] & 0xF) >= 0x8) // st (std) y
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) < 0x8) // st (std) z
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		handleUnimplemented();
	case 0x90:
	case 0x91:
		if ((memory[PC + 1] & 0xF) == 0x0) // lds
		{
			if (endian_switch)
				switch_higher_pc_content(PC + 2, PC + 3);
			ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)] = readMemory(((memory[PC + 2] << 8) | memory[PC + 3]));
			// No SREG_status Updates
			PC += 4;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x1) // ld z+
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory((ram[31] << 8) | ram[30]);
			// No SREG_status Updates
			if (ram[30] < 0xFF)
			{
				ram[30] = ram[30] + 1;
			}
			else
			{
				ram[31] = ram[31] + 1;
				ram[30] = 0x00;
			}
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x2) // ld -z
		{
			if (ram[30] == 0x00)
			{
				ram[30] = 0xFF;
				ram[31] = ram[31] - 1;
			}
			else
			{
				ram[30] = ram[30] - 1;
			}
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory((ram[31] << 8) | ram[30]);
			// No SREG_status Updates
			PC += 2;
			totalcycles += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x4) // lpm (rd, z)
		{
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory(2 * (((ram[31] << 8) | ram[30]) >> 1) + programStart + ((((ram[31] << 8) | ram[30]) & 0x1) == 0 ? 1 : 0));
			// No SREG_status Updates
			PC += 2;
			totalcycles += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x5) // lpm (rd, z+)
		{
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory(2 * (((ram[31] << 8) | ram[30]) >> 1) + programStart + ((((ram[31] << 8) | ram[30]) & 0x1) == 0 ? 1 : 0));
			// No SREG_status Updates
			if (ram[30] < 0xFF)
			{
				ram[30] = ram[30] + 1;
			}
			else
			{
				ram[31] = ram[31] + 1;
				ram[30] = 0x00;
			}
			PC += 2;
			totalcycles += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x7) // elpm
		{
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory(2 * (((ram[31] << 8) | ram[30]) >> 1) + programStart + ((((ram[31] << 8) | ram[30]) & 0x1) == 0 ? 1 : 0) + (memory[ATMEGA2560_RAMPZ] << 16));
			// No SREG_status Updates
			if (ram[30] < 0xFF)
			{
				ram[30] = ram[30] + 1;
			}
			else
			{
				ram[31] = ram[31] + 1;
				ram[30] = 0x00;
			}
			PC += 2;
			totalcycles += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x9) // ld y+
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory((ram[29] << 8) | ram[28]);
			// No SREG_status Updates
			if (ram[28] < 0xFF)
			{
				ram[28] = ram[28] + 1;
			}
			else
			{
				ram[29] = ram[29] + 1;
				ram[29] = 0x00;
			}
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xA) // ld -y
		{
			if (ram[28] == 0x00)
			{
				ram[28] = 0xFF;
				ram[29] = ram[29] - 1;
			}
			else
			{
				ram[28] = ram[28] - 1;
			}
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory((ram[29] << 8) | ram[28]);
			// No SREG_status Updates
			PC += 2;
			totalcycles += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xC) // ld x
		{
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory((ram[27] << 8) | ram[26]);
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xD) // ld x+
		{
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory((ram[27] << 8) | ram[26]);
			// No SREG_status Updates
			if (ram[26] < 0xFF)
			{
				ram[26] = ram[26] + 1;
			}
			else
			{
				ram[27] = ram[27] + 1;
				ram[26] = 0x00;
			}
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xE) // ld -x
		{
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			ram[result] = readMemory((ram[27] << 8) | ram[26] - 1);
			// No SREG_status Updates
			if (ram[26] > 0)
			{
				ram[26] = ram[26] - 1;
			}
			else
			{
				ram[27] = ram[27] - 1;
				ram[26] = 0xFF;
			}
			PC += 2;
			totalcycles += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xF) // pop
		{
			result = ((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4);
			incrementStackPointer();
			ram[result] = ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]];
			// No SREG_status Updates
			PC += 2;
			totalcycles++;

			break;
		}
		handleUnimplemented();
	case 0x92:
	case 0x93:
		if ((memory[PC + 1] & 0xF) == 0x0) // sts
		{
			if (endian_switch)
				switch_higher_pc_content(PC + 2, PC + 3);
			writeMemory(((memory[PC + 2] << 8) | memory[PC + 3]), ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)]);
			// No SREG_status Updates
			PC += 4;
			totalcycles += 1;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x1) // st (std) z+
		{
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			writeMemory((ram[31] << 8) | ram[30], result);
			// No SREG_status Updates
			if (ram[30] < 0xFF)
			{
				ram[30] = ram[30] + 1;
			}
			else
			{
				ram[31] = ram[31] + 1;
				ram[30] = 0x00;
			}
			PC += 2;
			totalcycles += 1;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x2) // st (std) -z
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			if (ram[30] == 0x00)
			{
				ram[30] = 0xFF;
				ram[31] = ram[31] - 1;
			}
			else
			{
				ram[30] = ram[30] - 1;
			}
			writeMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles += 1;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0x9) // st (std) y+
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[29] << 8) | ram[28]), result);
			// No SREG_status Updates
			if (ram[28] < 0xFF)
			{
				ram[28] = ram[28] + 1;
			}
			else
			{
				ram[29] = ram[29] + 1;
				ram[28] = 0x00;
			}
			PC += 2;
			totalcycles += 1;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xA) // st (std) -y
		{
			if (ram[28] == 0x00)
			{
				ram[29] = ram[29] - 1;
				ram[28] = 0xFF;
			}
			else
			{
				ram[28] = ram[28] - 1;
			}
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			totalcycles += 1;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xF) // push
		{
 			ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			decrementStackPointer();
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xC) // st x
		{
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			writeMemory((ram[27] << 8) | ram[26], result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xD) // st x+
		{
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			writeMemory((ram[27] << 8) | ram[26], result);
			// No SREG_status Updates
			if (ram[26] < 0xFF)
			{
				ram[26] = ram[26] + 1;
			}
			else
			{
				ram[27] = ram[27] + 1;
				ram[26] = 0x00;
			}
			PC += 2;
			totalcycles++;
			break;
		}
		if ((memory[PC + 1] & 0xF) == 0xE) // st -x
		{
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			if (ram[26] == 0x00)
			{
				ram[26] = 0xFF;
				ram[27] = ram[27] - 1;
			}
			else
			{
				ram[26] = ram[26] - 1;
			}
			writeMemory((ram[27] << 8) | ram[26], result);
			// No SREG_status Updates
			PC += 2;
			totalcycles++;
			break;
		}
		handleUnimplemented();
	case 0x94:
	case 0x95:
		if ((memory[PC] == 0x94) && (memory[PC + 1] == 0x08)) // sec
		{
			newStatus.C = SET;
			PC += 2;
			break;
		}
		if ((memory[PC] == 0x94) && (memory[PC + 1] == 0x09)) // ijmp
		{
			result = (2 * ((ram[31] << 8) | ram[30])) + programStart;
			// No SREG_status Updates
			PC = result;
			totalcycles++;
			break;
		}
		if ((memory[PC] == 0x94) && (memory[PC + 1] == 0x68)) // set
		{
			newStatus.T = SET;
			PC += 2;
			break;
		}
		if ((memory[PC] == 0x94) && (memory[PC + 1] == 0x78)) // sei
		{
			newStatus.I = SET;
			PC += 2;
			break;
		}
		if ((memory[PC] == 0x94) && (memory[PC + 1] == 0xE8)) // clt
		{
			newStatus.T = CLR;
			PC += 2;
			break;
		}
		if ((memory[PC] == 0x94) && (memory[PC + 1] == 0xF8)) // cli
		{
			newStatus.I = CLR;
			PC += 2;
			break;
		}
		if ((memory[PC + 1] == 0x88) || (memory[PC + 1] == 0xA8)) // sleep || wdr
		{
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((memory[PC] == 0x95) && (memory[PC + 1] == 0x8)) // ret
		{
			incrementStackPointer();
			result = (ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS];
			// No SREG_status Updates
			incrementStackPointer();
#ifndef ATMEGA2560
			PC = ((ram[result] << 8) | (ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]]));
#else
			result = ((ram[result] << 16) | (ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]]) << 8);
			incrementStackPointer();
			PC = result | (ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]]);
			totalcycles += 3;
#endif
			stop_fetch = 1;
			break;
		}
		if ((memory[PC] == 0x95) && (memory[PC + 1] == 0x9)) // icall
		{
			result = (((ram[31] << 8) | ram[30]) * 2) + programStart;
			PC += 2;

			ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF);
			decrementStackPointer();
			ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF00) >> 8;
			decrementStackPointer();
#ifdef ATMEGA2560
			ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = 0x00;
			decrementStackPointer();
			totalcycles += 2;
#endif
			// No SREG_status Updates
			PC = result;
			break;
		}
		if ((memory[PC] == 0x95) && (memory[PC + 1] == 0x18)) // reti
		{
			incrementStackPointer();
			result = (ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS];
			incrementStackPointer();
			newStatus.I = SET;
#ifndef ATMEGA2560
			PC = (ram[result] | ((ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]]) << 8));
#else
			incrementStackPointer();
			PC |= ((ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]]) << 16);
			totalcycles += 3;
#endif
			break;
		}
		switch (memory[PC + 1] & 0x0F)
		{
		case 0x0: // com
			result = ~ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
			newStatus.V = CLR;
			newStatus.C = SET;
			newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
			newStatus.Z = result == 0x00 ? SET : CLR;
			newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
			PC += 2;
			break;
		case 0x1: // neg
			if (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] != 0x80)
			{
				result = (~ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] + 1) & 0xFF;
				ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
			}
			newStatus.H = generateHStatus_Neg(ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)]);
			newStatus.V = result == 0x80 ? SET : CLR;
			newStatus.C = result == 0x00 ? CLR : SET;
			newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
			newStatus.Z = result == 0x00 ? SET : CLR;
			newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
			PC += 2;
			break;
		case 0x2: // swap
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] << 4;
			result |= (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] >> 4);
			ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
			PC += 2;
			break;
		case 0x3: // inc
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			newStatus.V = result == 0x7F ? SET : CLR;
			ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = ++result;
			newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
			newStatus.Z = (result & 0xFF) == 0x00 ? SET : CLR;
			newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
			PC += 2;
			break;
		case 0x5: // asr
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			newStatus.C = (result & 0x1) > 0 ? SET : CLR;
			result = ((result >> 1) | (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] & 0x80));
			newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
			newStatus.V = ((newStatus.N ^ newStatus.C) > 0) ? SET : CLR;
			newStatus.Z = result == 0x00 ? SET : CLR;
			newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
			ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
			PC += 2;
			break;
		case 0x6: // lsr
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			newStatus.C = (result & 0x1) > 0 ? SET : CLR;
			result = (result >> 1);
			newStatus.N = CLR;
			newStatus.V = ((newStatus.N ^ newStatus.C) > 0) ? SET : CLR;
			newStatus.Z = result == 0x00 ? SET : CLR;
			newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
			ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
			PC += 2;
			break;
		case 0x7: // ror
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			newStatus.C = (result & 0x1) > 0 ? SET : CLR;
			result = ((result >> 1) | (SREG_status.C << 7));
			newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
			newStatus.V = ((newStatus.N ^ newStatus.C) > 0) ? SET : CLR;
			newStatus.Z = result == 0x00 ? SET : CLR;
			newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
			ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = result;
			PC += 2;
			break;
		case 0xA: // dec
			result = ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)];
			newStatus.V = result == 0x80 ? SET : CLR;
			ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] = --result;
			newStatus.N = ((result & 0x80) > 0) ? SET : CLR;
			newStatus.Z = result == 0x00 ? SET : CLR;
			newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
			PC += 2;
			break;
		case 0xC:
		case 0xD: // jmp
			// No SREG_status Updates
			result = (memory[PC] & 0x1) << 21;
			result += (memory[PC + 1] >> 4) << 17;
			result += (memory[PC + 1] & 0x1) << 16;
			if (endian_switch)
				switch_higher_pc_content(PC + 2, PC + 3);
			result += (memory[PC + 2] << 8 | memory[PC + 3]);
			PC = programStart + (result * 2);
			totalcycles += 2;
			break;
		case 0xE:
		case 0xF: // call
			if (endian_switch)
				switch_higher_pc_content(PC + 2, PC + 3);
			result = programStart + (((memory[PC] & 0x1) << 21) | ((memory[PC + 1] & 0xF0) << 17) | ((memory[PC + 1] & 0x1) << 16) | (memory[PC + 2] << 8) | memory[PC + 3]) * 2;

			PC += 4;
			ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF);
			decrementStackPointer();
			ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF00) >> 8;
			decrementStackPointer();
#ifdef ATMEGA2560
			ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF0000) >> 16;
			decrementStackPointer();
			totalcycles += 3;
#endif
			// No SREG_status Updates
			PC = result;
			break;
		default:
			handleUnimplemented();
			break;
		}
		break;
	case 0x96: // adiw
	case 0x97: // sbiw
		result = ((memory[PC + 1] & 0x30) >> 4);
		switch (result)
		{
		case 0:
			result = 24;
			break;
		case 1:
			result = 26;
			break;
		case 2:
			result = 28;
			break;
		case 3:
			result = 30;
			break;
		default:
			handleUnimplemented();
		}
		result = (ram[result + 1] << 8) | ram[result];
		result_old = result; 
		newStatus.V = generateVStatus(result, (((memory[PC + 1] & 0xC0) >> 0x2) | (memory[PC + 1] & 0xF)));
		//newStatus.C = abs((((memory[PC + 1] & 0xC0) >> 0x2) | (memory[PC + 1] & 0xF))) > abs(result) ? SET : CLR;
		if (memory[PC] == 0x96)
		{
			result = result + (((memory[PC + 1] & 0xC0) >> 0x2) | (memory[PC + 1] & 0xF));
			newStatus.C =  (result_old > result)? SET:CLR;
			  
		}
		if (memory[PC] == 0x97)
		{
			result = result - (((memory[PC + 1] & 0xC0) >> 0x2) | (memory[PC + 1] & 0xF));
			newStatus.C =  (result_old < result)? SET:CLR;
		}
		
		
		newStatus.N = ((result & 0x8000) > 0) ? SET : CLR;
		newStatus.Z = result == 0x0000 ? SET : CLR;
		newStatus.S = ((newStatus.N ^ newStatus.V) > 0) ? SET : CLR;
		switch ((memory[PC + 1] & 0x30) >> 4)
		{
		case 0:
			ram[24] = result & 0xFF;
			ram[25] = (result & 0xFF00) >> 8;
			break;
		case 1:
			ram[26] = result & 0xFF;
			ram[27] = (result & 0xFF00) >> 8;
			break;
		case 2:
			ram[28] = result & 0xFF;
			ram[29] = (result & 0xFF00) >> 8;
			break;
		case 3:
			ram[30] = result & 0xFF;
			ram[31] = (result & 0xFF00) >> 8;
			break;
		default:
			handleUnimplemented();
		}
		PC += 2;
		totalcycles++;
		break;
	case 0x98: // cbi
		result = (1 << (memory[PC + 1] & 0x7));
		ram[(memory[PC + 1] >> 0x3) + IO_REG_START] &= ~result;
		// No SREG_status Updates
		PC += 2;
		totalcycles++;
		break;
	case 0x9A: // sbi
		result = (1 << (memory[PC + 1] & 0x7));
		ram[(memory[PC + 1] >> 0x3) + IO_REG_START] |= result;
		// No SREG_status Updates
		PC += 2;
		totalcycles++;
		break;
	case 0x9B: // sbis
		result = ram[(memory[PC + 1] >> 0x3) + IO_REG_START];
		if ((result & (1 << (memory[PC + 1] & 0x7))) > 0)
		{
			PC += 2;
			totalcycles++;
			if (longOpcode(PC))
			{
				PC += 2;
				totalcycles++;
			}
		}
		// No SREG_status Updates
		PC += 2;
		break;
	case 0x9C:
	case 0x9D:
	case 0x9E:
	case 0x9F: // mul
		result = (ram[((memory[PC] & 0x1) << 4) | (memory[PC + 1] >> 4)] * ram[(((memory[PC] & 0x2) >> 1) << 4) | (memory[PC + 1] & 0xF)]);
		newStatus.Z = result == 0x0000 ? SET : CLR;
		newStatus.C = ((result & 0x8000) > 0) ? SET : CLR;
		ram[1] = result >> 8;
		ram[0] = result & 0xFF;
		PC += 2;
		break;
	case 0xA0:
	case 0xA1:
	case 0xA4:
	case 0xA5:
	case 0xA8:
	case 0xA9:
	case 0xAC:
	case 0xAD:
		if ((memory[PC + 1] & 0xF) < 0x8) // ld (ldd) z
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) >= 0x8) // ld (ldd) y
		{
			result = ((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4);
			ram[result] = readMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)));
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0xA2:
	case 0xA3:
	case 0xA6:
	case 0xA7:
	case 0xAA:
	case 0xAB:
	case 0xAE:
	case 0xAF:
		if ((memory[PC + 1] & 0xF) < 0x8) // st (std) z
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[31] << 8) | ram[30]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((memory[PC + 1] & 0xF) >= 0x8) // st (std) y
		{
			result = ram[((memory[PC] & 0x1) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			writeMemory(((ram[29] << 8) | ram[28]) + (((memory[PC] & 0xC) << 1) | (memory[PC + 1] & 0x7) | (((memory[PC] >> 1) & 0x10) << 1)), result);
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0xB0:
	case 0xB1:
	case 0xB2:
	case 0xB3:
	case 0xB4:
	case 0xB5:
	case 0xB6:
	case 0xB7: // in
		ram[((memory[PC] & 0x01) << 4) | ((memory[PC + 1] & 0xF0) >> 4)] = readMemory(((((memory[PC] & 0x07) >> 1) << 4) | (memory[PC + 1] & 0x0F)) + IO_REG_START);
		// No SREG_status Updates
		PC += 2;
		break;
	case 0xB8:
	case 0xB9:
	case 0xBA:
	case 0xBB:
	case 0xBC:
	case 0xBD:
	case 0xBE:
	case 0xBF: // out
		writeMemory(((((memory[PC] & 0x07) >> 1) << 4) | (memory[PC + 1] & 0x0F)) + IO_REG_START, ram[((memory[PC] & 0x01) << 4) | ((memory[PC + 1] & 0xF0) >> 4)]);
		// No SREG_status Updates
		PC += 2;
		break;
	case 0xC0:
	case 0xC1:
	case 0xC2:
	case 0xC3:
	case 0xC4:
	case 0xC5:
	case 0xC6:
	case 0xC7:
	case 0xC8:
	case 0xC9:
	case 0xCA:
	case 0xCB:
	case 0xCC:
	case 0xCD:
	case 0xCE:
	case 0xCF: // rjmp
		if ((memory[PC] == 0xCF) && (memory[PC + 1] == 0xFF))
		{
			// Program Exit
			return false;
		}
		result = ((memory[PC] & 0xF) << 8) | memory[PC + 1];
		PC += 2;
		totalcycles += 1;
		PC = (0x800 == (result & 0x800)) ? PC - (0x1000 - (2 * (result ^ 0x800))) : PC + (2 * result);
		// No SREG_status Updates
		break;
	case 0xD0:
	case 0xD1:
	case 0xD2:
	case 0xD3:
	case 0xD4:
	case 0xD5:
	case 0xD6:
	case 0xD7:
	case 0xD8:
	case 0xD9:
	case 0xDA:
	case 0xDB:
	case 0xDC:
	case 0xDD:
	case 0xDE:
	case 0xDF: // rcall
		result = ((memory[PC] & 0xF) << 8) | memory[PC + 1];
		PC += 2;
		ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF);
		decrementStackPointer();
		ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF00) >> 8;
		decrementStackPointer();
#ifdef ATMEGA2560
		ram[(ram[SPH_ADDRESS] << 8) | ram[SPL_ADDRESS]] = (PC & 0xFF0000) >> 16;
		decrementStackPointer();

#endif
		// No SREG_status Updates
		if (0x800 == (result & 0x800))
		{
			PC -= (0x1000 - 2 * (result ^ 0x800));
		}
		else
		{
			PC += (2 * result);
		}
		totalcycles += 2;
		break;
	case 0xE0:
	case 0xE1:
	case 0xE2:
	case 0xE3:
	case 0xE4:
	case 0xE5:
	case 0xE6:
	case 0xE7:
	case 0xE8:
	case 0xE9:
	case 0xEA:
	case 0xEB:
	case 0xEC:
	case 0xED:
	case 0xEE:
	case 0xEF: // ldi
		ram[16 + ((memory[PC + 1] & 0xF0) >> 4)] = ((memory[PC] & 0xF) << 4) | (memory[PC + 1] & 0xF);
		// No SREG_status Updates
		PC += 2;
		break;
	case 0xF0:
	case 0xF1:
	case 0xF2:
	case 0xF3:
		if ((((memory[PC] & 0x0C) >> 2) == 0x0) && ((memory[PC + 1] & 0x7) == 0x0)) // brcs
		{
			if (SREG_status.C == SET)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x0) && ((memory[PC + 1] & 0x7) == 0x1)) // breq
		{
			if (SREG_status.Z == SET)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x0) && ((memory[PC + 1] & 0x7) == 0x2)) // brmi
		{
			if (SREG_status.N == SET)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x0) && ((memory[PC + 1] & 0x7) == 0x4)) // brlt
		{
			if (SREG_status.S == SET)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x0) && ((memory[PC + 1] & 0x7) == 0x6)) // brts
		{
			if (SREG_status.T == SET)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0xF4:
	case 0xF5:
	case 0xF6:
	case 0xF7:
		if ((((memory[PC] & 0x0C) >> 2) == 0x1) && ((memory[PC + 1] & 0x7) == 0x2)) // brpl
		{
			if (SREG_status.N == CLR)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
				totalcycles++;
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x1) && ((memory[PC + 1] & 0x7) == 0x0)) // brcc
		{
			if (SREG_status.C == CLR)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
				totalcycles++;
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x1) && ((memory[PC + 1] & 0x7) == 0x1)) // brne
		{
			if (SREG_status.Z == CLR)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
				totalcycles++;
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x1) && ((memory[PC + 1] & 0x7) == 0x4)) // brge
		{
			if (SREG_status.S == CLR)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
				totalcycles++;
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		if ((((memory[PC] & 0x0C) >> 2) == 0x1) && ((memory[PC + 1] & 0x7) == 0x6)) // brtc
		{
			if (SREG_status.T == CLR)
			{
				result = ((memory[PC] & 0x3) << 5) | (memory[PC + 1] >> 3);
				PC = (0x40 < result) ? (PC - (2 * (0x80 - result))) : (PC + (2 * result));
				totalcycles++;
			}
			// No SREG_status Updates
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0xF8:
	case 0xF9: // bld
		if ((memory[PC + 1] & 0xF) < 0x8)
		{
			if (SREG_status.T == SET)
			{
				ram[((memory[PC] & 0x01) << 4) | ((memory[PC + 1] & 0xF0) >> 4)] |= (1 << (memory[PC + 1] & 0x7));
			}
			else
			{
				ram[((memory[PC] & 0x01) << 4) | ((memory[PC + 1] & 0xF0) >> 4)] &= ~(1 << (memory[PC + 1] & 0x7));
			}
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0xFA:
	case 0xFB: // bst
		result = ram[((memory[PC] & 0x01) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
		newStatus.T = (result & (1 << (memory[PC + 1] & 0x7))) > 0 ? SET : CLR;
		PC += 2;
		break;
	case 0xFC:
	case 0xFD: // sbrc
		if ((memory[PC + 1] & 0xF) < 0x8)
		{
			result = ram[((memory[PC] & 0x01) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			if ((result & (1 << (memory[PC + 1] & 0xF))) == 0)
			{
				PC += 2;
				totalcycles++;
				if (longOpcode(PC))
				{
					PC += 2;
					totalcycles++;
				}
			}
			PC += 2;
			break;
		}
		handleUnimplemented();
	case 0xFE:
	case 0xFF: // sbrs
		if ((memory[PC + 1] & 0xF) < 0x8)
		{
			result = ram[((memory[PC] & 0x01) << 4) | ((memory[PC + 1] & 0xF0) >> 4)];
			if ((result & (1 << (memory[PC + 1] & 0xF))) > 0)
			{
				PC += 2;
				totalcycles++;
				if (longOpcode(PC))
				{
					PC += 2;
					totalcycles++;
				}
			}
			PC += 2;
			break;
		}
		handleUnimplemented();
	default:
		handleUnimplemented();
		break;
	}

	pushStatus(&newStatus);
	// resetFetchState();

	return true;
}

void resetFetchState()
{
	 
}

uint8_t readMemory(int32_t address)
{
	 
	if (address - 0x2000 < 0x4050 - address)
	{
	    uint8_t value;
	    uint8_t *ptr = (uint8_t*)address;

	    // Dereference the pointer to read the value at the address
	    value = *ptr;
		return value;
	}
	
	else
	return ram[address];
}

void writeMemory(int32_t address, int32_t value)
{
	 
	if (address - 0x2000 < 0x4050 - address)
	{
		uint8_t *ptr = (uint8_t*)address;

		// Dereference the pointer to read the value at the address
		*ptr = value;
	
	}
	
	else
	ram[address] = value;
	
	 
}

uint16_t totalFetches = 0;

int main()
{

	totalinstructions = totalcycles = 0;

	// binary point to array to storing the exetuble

	uint8_t *binary;

	// point to load

	// loadProgram(binary);

	// loadDefaultProgram();

	   

	 
	ram[16] = 1;
	ram[17] = 2;
	ram[18] = 3;
	ram[19] = 4;
	ram[20] = 5;
	ram[21] = 6;
	ram[22] = 7;
	ram[23] = 8;
	ram[24] = 9;
	ram[25] = 10;
	ram[26] = 11;
	ram[27] = 12;
	ram[28] = 0x00;
	ram[29] = 0x40;
	ram[30] = 15;
	ram[31] = 16;
	
	
	ram[SPH_ADDRESS] = 0x40;
	ram[SPL_ADDRESS] = 0x00;
	
	#ifdef VM_UN_SET
	
	//Use bubblesort as example 
	bubble_sort();
	

   #endif 
  
	read_flash_code(memory);
	engineInit();
	execProgram();


    //test_random2();
	// foo_location_specific();
	while (1)
	{
	}
	return 0;
}

