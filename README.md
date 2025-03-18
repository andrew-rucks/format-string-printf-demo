# format-string-printf-demo

There was a challenge in PicoCTF 2025 that involved exploiting a format string vulnerability. This entailed passing a precise format string to printf() that causes it to write the address of a target function to an address in the stack (that would be jumped to as a return).

The target was a simple echo program: it asks for input, and then says the input right back. The vulnerability was that the input buffer was passed directly to printf() with no sanitization.

Here are some additional resources: https://hackinglab.cz/en/blog/format-string-vulnerability/
https://docs.pwntools.com/en/stable/
https://www.exploit-db.com/papers/13239

DISCLAIMER: THIS IS FOR EDUCATIONAL / CAPTURE THE FLAG PURPOSES ONLY.

