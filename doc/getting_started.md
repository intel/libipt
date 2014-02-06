Getting Started
===============

We start by compiling an existing test, which consists of a small assembly
program with interleaved PT directives:

	$ pttc test/src/loop.ptt
	loop-ptxed.exp
	loop-ptdump.exp

This produces the following output files:

	loop.lst          a yasm assembly listing file
	loop.bin          a raw binary file
	loop.pt           a PT file
	loop-ptxed.exp    the expected ptxed output
	loop-ptdump.exp   the expected ptdump output

The latter two files are generated based on the `@pt .exp(<tool>)` directives
found in the `.ptt` file.  They are used for automated testing but are otherwise
not interesting for us at this point (see the pttc article).


Let's dump the PT packets:

	$ ptdump loop.pt
	0000000000000000  psb
	0000000000000010  fup        3: 0x0000000000100000, ip=0x0000000000100000
	0000000000000017  mode.exec  cs.d=0, cs.l=1 (64-bit mode)
	0000000000000019  psbend
	000000000000001b  tnt8       !!.
	000000000000001c  tip.pgd    3: 0x0000000000100013, ip=0x0000000000100013

The ptdump tool takes a PT file as input and dumps the packets in a more or less
human-readable form.  The number on the very left is the offset into the PT
stream in hex.  This is followed by the PT packet opcode and the packet payload.


Now let's reconstruct the control flow.  For this, we need the PT as well as the
corresponding binary image.  We need to specify the load address given by the
org directive in the .ptt file when we use a raw binary file.

	$ ptxed --pt loop.pt --raw loop.bin:0x100000
	0x0000000000100000  mov rax, 0x0
	0x0000000000100007  jmp 0x10000d
	0x000000000010000d  cmp rax, 0x1
	0x0000000000100011  jle 0x100009
	0x0000000000100009  add rax, 0x1
	0x000000000010000d  cmp rax, 0x1
	0x0000000000100011  jle 0x100009
	0x0000000000100009  add rax, 0x1
	0x000000000010000d  cmp rax, 0x1
	0x0000000000100011  jle 0x100009
	[disabled]

Ptxed prints disassembled instructions in execution order as well as status
messages enclosed in brackets.
