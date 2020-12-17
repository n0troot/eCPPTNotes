# eCPPTNotes

## eCPPT ##

Architecture Fundamentals ::
	
	CPU:
		CPU Instructions are represented in hexadecimal(HEX).
		The instructions are complex to read(machine code), thus they're getting translated into Assembly code(ASM) which is human-readable.

		Each CPU has it's own ISA - Instruction set architecture,
		ISA is what a programmer can see:
			-memory
			-registers
			-instructions
			-etc.
			Provides all the necessary info for who want to write a program in that machine lang.
			Examples are: Intel 8086 - x86, AMD64 - x64
	Registers:
		number of bits 32,64 refers to the width of the CPU registers.
		Each CPU has its fixed set of registers that are accessed when required.
		General Purpose Registers (GPRs):
			EAX - Accumulator   	  - Used in arithmetic operations
			ECX - Counter       	  - Used in shift/rotate instr. and loops
			EDX - Data          	  - Used in arithmetic operations & I/O
			EBX - Base          	  - Used as a pointer to data
			ESP - Stack Pointer 	  - Pointer to the top of the stack
			EBP - Base Pointer  	  - Pointer to the base of the stack
			ESI - Source Index        - Used as a pointer to a source in stream operation
			EDI - Destination         - Used as a pointer to a destination in stream operation
			EIP - Instruction Pointer - tells the CPU where the next instuction is
	Process Memory:
		Text:
			The text region, or instr. segment, is fixed by the program and a contains the program code(instructions). - read-only.
		Data:
			The data region is divided into initialized data and uninitialized data.
			initialized data includes items such as static and global declared variables that are pre-defined and can be modified.
			uninitialized data, named 'Block Started by Symbol'(BSS), also initializes variables that are initialized to zero or do not have explicit initialization(C++ ex. : int t;)
		Heap:
			Starts right after BSS, during the execution the program can request more space in memory via brk and sbrk system calls, used by malloc(memory allocate) and realloc(re-allocate) and free. Hence, the size of the data region can be extended; this is not vital.
		Stack:
			The stack is a LIFO(Last in first out) block of memory. It is located in the higher part of the memory. Can be thought as an array used for saving a fucntion's return addresses, passing function arguments, and storing local variables.
			ESP:
				The purpose of the ESP register(Stack Pointer) is to identify the top of the stack,
				and it is modified each time a value is pushed in(PUSH) or popped out(POP).
			PUSH:
				A PUSH instruction subtracts 4(32-bit) or 8(64-bit) from the ESP and writes the data to the memory address in the ESP, then updates the ESP to the top of the stack.
				Stack grows backwards, therefore the PUSH substracts 4 or 8, in order to point to a lower memory location on the stack. If we don't subtract it, the PUSH operation will overwrite the current location pointed by ESP(the top) and we'd lose data.
			POP:
				Opposite of the PUSH instruction, it retrieves data from the top of the stack.
				Therefore, the data contained in the address location in ESP is retrieved and stored(usually in another register). After a POP operation, the ESP value is incremented, by 4 or by 8.
			Procedures and Fucntions:
				Stack Frames:
					Functions contain two important components, the prologue and the epilogue.
					The prologue prepares the stack to be used, similar to putting a bookmark in a book. when the function has completed, the epilogue resets the stack to the prologue settings.
					The stack consists of logical stack frames(portions/areas of the stack), that are PUSHed when calling a function and POPed when returning a value.
					When a subroutine, such as a function or procedure, is started, a stack frame is created and assigned to the current ESP location(top of stack); this allows the subroutine to operate independently in its own location in the stack.
					When a subroutine ends:
						1. The program recieves the parameters passed form the subroutine.
						2. The insturction Pointer(EIP) is reset to the location at the time of the initial call.
						The stack frame keeps track of the location where each subroutine should return the control when it terminates.
					when a functions is called, the arguments [(in brackets)] need to be evaluated.
					The control flow jumps to the body of the function, and the program executes its code.
					Once the function ends, a return statement is encountered, the program returns to the function call(the next statement in the code).
					When a new function is called, a new stack frame has to be created.
					the stack frame is defined by the EBP(Base Pointer) and the ESP(Stack Pointer)... the bottom and the top of the stack.
					For us to not lose the information of the old stack frame, which is the function that called the current function, we have to save the current EBP on the stack.
					If not done, we wouldn't know that this info belonged to a previous stack frame when returned.

					Prologue:
						Example of a function call:
							1. push ebp
							2. mov ebp, esp
							3. sub esp, X(number)

							1. push ebp:
								The first instruction saves the old EBP onto the stack, so it could be restored later.
							2. mov ebp, esp:
								The second instuction copies ESP value to EBP.
							3. sub esp, x:
								The last instruction moves the ESP by decreasing it's value, necessary for making space for the local variables.

					Epilogue:
						Example of a function pop:
							1. mov esp, ebp
							2. pop ebp
							3. ret

							1. mov esp, ebp:
								The first instruction makes both the ESP and EBP point to the same location.
							2. pop ebp:
								The second instruction removes the value of EBP from the stack, sinch the top of the stack points to the old EBP, the stack frame is restored. (and ESP points to the old EIP previously stored)
							3. ret:
								The last instruction pops the value contained at the top of the stack to the old EIP - The next instruction after the call and jumps to that location.
								RET affects only the EIP and the ESP registers.


				Endianness:
					The way of storing data in the memory.
					MSB - Most significant bit - in a binary number is the largest value, usually the first from the left.
					example:
						binary is - 100, MSB is 1.
					LSB - Least significant bit - in a binary number is the smallest value, usually the first from the right.
					example:
						binary is - 100, LSB is 0.

					Big-Endian:
						In the big-endian representation, the LSB is stored at the highest memory address, while the MSB at the lowest.
					Little-Endian:
						In the little-endian representation, the LSB is stored at the lowest memory address, while the MSB at the highest.

				NOPs:
					NOP is an Assembly language instruction that does nothing(NOP=No operation instruction).
					When a program encounters a NOP, it skips to the next instruction. in x86 represented by HEX value of 0x90.

					NOP-sled:
						NOP-sled is a technique used during exploitation process of buffer overflows. Its only purpose is to fill a large(or small) portion of the stack with NOPs; this will allow us to slide down to the instruction we want to execute, which is usually put after the NOP-sled.
						That's because BOF(buffer overflow) have to match a specific size and location that the program is expecting.

Security Implementations ::

	ASLR:
		Address Space Layout Randomization(ASLR)
		The goal is to introduce randomness for executables, libraries, and stacks in the memory address space.
		Makes it difficult for an attacker to predict memory addresses and exploit.
		When ASLR is loaded the OS loads the same executable at different locations in memory every time.
		*ASLR is not enabled for all modules, means that there could be a DLL in the address space without the protection, making the whole prgoram vulnerable*

		Verify ASLR:
			-Process Explorer

		Mitigation:
			Enhanced Mitigation Experience Toolkit(EMET)

			DEP:
				Defensive hardware and software measure that prevents the execution of code from pages in memory that are not explicitly makred as executables.
				Code Injected into the memory can't be run from this region.

			The Canary(Stack Cookie):
				A security measure, places a value next to the return address in the stack.
				The function prologue loads a value into this location, while the epilogue makes sure that the value is intact.
				As a result, when the epilogue runs, it checks that the value is still there and that it is correct.


Assembly ::
	
	NASM:
		Assemble - nasm -f win32 file.asm -o output.obj
		Link DLLs - GoLink.exe /entry _main output.obj 1_dll.dll 2_dll.dll
			/entry _main - tells the linker the entry point for the program

	ASM Basics:
		Instructions:
			Data Transfer:
				MOV  - Moves data from one location to another on the memory
				XCHG - Exchange the data of two operands (but not between memory)
				PUSH - Pushes a value into the stack
				POP  - Deletes a value off the stack
			Arithmetic:
				ADD  - Increment
				SUB  - Subtract
				MUL  - Multiply
				XOR  - Exclusive or (outputs true only if when input differ, one is true and other is false)
				NOT  - same as '!'
			Control Flow:
				CALL - CALL a function 
				RET  - Return, end function
				LOOP - 
				Jc   - (c - condition) jump if NE(not equal), E(equal), NZ(not zero), JGE(greater or equal), etc.
			Other:
				STI  -
				CLI  -
				IN   -
				OUT  -

		Intel vs AT&T:
			Intel(Windows) - <instruction><destination><source>
			AT&T(Linux)    - <instruction><source><destination>
				puts % before registers and a $ before numbers.
				suffix to the instuction to define operand size as well:
					Q-quad(64bit), L-Long(32bit), W-Word(16bit), B-Byte(8bit)

		PUSH instruction:
			PUSH stores a value on the top of the stack, causing the stack to be adjusted by -4 bytes (on 32-bit), -0x04.
			PUSH under the hood just subtracts -4 from the ESP.

		POP instruction:
			POP reads the value from the top of the stack, causing the stack to be adjusted by +4 bytes, +0x04.
			Adds +4 to the ESP.

		CALL instruction:
			Subroutines are implemented by using the CALL and RET instruction pair.
			The CALL instruction pushes the current instruction pointer(EIP) to the stack and jumps to the function address specified.
			Whenever the function executes the RET instruction, the last element is popped from the stack, and the CPU jumps to the address.


Tools ::
	
	gcc - gcc -m32(architecture) file.c -o(output) file.exe
	objdump - objdump -d(disassemble) -Mintel(architecture) file.exe > assembly.txt




Buffer Overflows ::
	
	
