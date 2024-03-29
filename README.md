# Asmshell

A python x86_64 REPL based on keystone + unicorn + capstone.

# Run project (for users)

```console
$ curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python - # Poetry installation
$ poetry install
$ poetry run asmshell
```

# Run project (for devs)

```console
$ curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python - # Poetry installation
$ poetry config virtualenvs.in-project true
$ poetry install
$ pip3 install --user pre-commit # Pre-commit installation
$ poetry run pre-commit install
$ poetry run test
$ poetry run asmshell
```

# Commands

The prompt allows you to type ASM but there are also some extra commands available:

```console
Commands:
 .h, .help:            This help
 .q, .quit:            Quit this program
 .cls, .clear:         Clear screen
 .r, .reg, .registers: Display registers
 .s, .stack:           Display the stack
 .rb:                  Read byte values
 .rw:                  Read word values
 .rd:                  Read double-word values
 .rq:                  Read quad-word values
 .rm:                  Read memory
 .ri:                  Read instructions
 .wb:                  Write byte(s) values
 .d, .dump:            Dump state to file
 .dec, .decode:        Decode instruction
```

# Examples

## Running code

From the `xorpd`'s `xchg rax,rax` [snippet 0x09](https://www.xorpd.net/pages/xchg_rax/snip_09.html):

```console
> mov rax, 4
Code:
0000000000000000: 48 c7 c0 04 00 00 00     | mov rax, 4
Registers:
rax:    0000000000000004  r8:  0000000000000000  cs: 0000000000000000  cr0: 0000000000000011 [ PE ET ]
rbx:    0000000000000000  r9:  0000000000000000  ss: 0000000000000000  cr1: 0000000000000000
rcx:    0000000000000000  r10: 0000000000000000  ds: 0000000000000000  cr2: 0000000000000000
rdx:    0000000000000000  r11: 0000000000000000  es: 0000000000000000  cr3: 0000000000000000
rdi:    0000000000000000  r12: 0000000000000000  fs: 0000000000000000  cr4: 0000000000000000 [  ]
rsi:    0000000000000000  r13: 0000000000000000  gs: 0000000000000000
rbp:    0000000000000000  r14: 0000000000000000
rsp:    0000000000200000  r15: 0000000000000000
rip:    0000000000000007
eflags: 0000000000000002 [  ]
Stack:
0000000000200000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
————————————————————————————————————————————————————————————————————————————————————————————————————————
> shr rax, 3
Code:
0000000000000007: 48 c1 e8 03              | shr rax, 3
Registers:
rax:    0000000000000000  r8:  0000000000000000  cs: 0000000000000000  cr0: 0000000000000011 [ PE ET ]
rbx:    0000000000000000  r9:  0000000000000000  ss: 0000000000000000  cr1: 0000000000000000
rcx:    0000000000000000  r10: 0000000000000000  ds: 0000000000000000  cr2: 0000000000000000
rdx:    0000000000000000  r11: 0000000000000000  es: 0000000000000000  cr3: 0000000000000000
rdi:    0000000000000000  r12: 0000000000000000  fs: 0000000000000000  cr4: 0000000000000000 [  ]
rsi:    0000000000000000  r13: 0000000000000000  gs: 0000000000000000
rbp:    0000000000000000  r14: 0000000000000000
rsp:    0000000000200000  r15: 0000000000000000
rip:    0000000000000004
eflags: 0000000000000047 [ CF PF ZF ]
Stack:
0000000000200000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
————————————————————————————————————————————————————————————————————————————————————————————————————————
> adc rax, 0
Code:
0000000000000004: 48 83 d0 00              | adc rax, 0
Registers:
rax:    0000000000000001  r8:  0000000000000000  cs: 0000000000000000  cr0: 0000000000000011 [ PE ET ]
rbx:    0000000000000000  r9:  0000000000000000  ss: 0000000000000000  cr1: 0000000000000000
rcx:    0000000000000000  r10: 0000000000000000  ds: 0000000000000000  cr2: 0000000000000000
rdx:    0000000000000000  r11: 0000000000000000  es: 0000000000000000  cr3: 0000000000000000
rdi:    0000000000000000  r12: 0000000000000000  fs: 0000000000000000  cr4: 0000000000000000 [  ]
rsi:    0000000000000000  r13: 0000000000000000  gs: 0000000000000000
rbp:    0000000000000000  r14: 0000000000000000
rsp:    0000000000200000  r15: 0000000000000000
rip:    0000000000000004
eflags: 0000000000000002 [  ]
Stack:
0000000000200000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
0000000000200030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
————————————————————————————————————————————————————————————————————————————————————————————————————————
> .quit
```

## Instruction decoding example

```console
> .wb 0 666690
> .dec 0
Instruction details:
mnemonic:     nop
bytes:        0x66 0x66 0x90
prefix:       0x00 0x00 0x66 0x00
opcode:       0x90 0x00 0x00 0x00
rex:          0x00
addr size:    0x08
modrm:        0x00 (mod: 0b00) (reg: 0b000) (rm: 0b000)
modrm offset: 0x00
disp:         0x00
sib:          0x00 (scale: 0b00) (index: 0b000) (base: 0b000)
```

# Other features

* Fully featured prompt (arrow keys, history, commands auto-completion)
* Updated registers highlighting

# Run tests

```console
$ poetry run test
```

OR

```console
$ poetry run coverage
$ firefox htmlcov/index.html &
```

# Missing features

* int 0x80
* obscure features like freep

# Similar projects

* https://github.com/yrp604/rappel/
* https://github.com/poppycompass/asmshell/
* https://github.com/Tyilo/asm_repl
