# Mini memcheck
Very basic *Valgrind* memcheck implementation to detect memory leaks.  
Based on coursework by Jean-Michel Gorius, adapted for MacOS compatibility.

## Example output
```
==4723== Mini-Memcheck
==4723==
==4723== LEAK REPORT:
==4723== Leak origin: main (test.c:5)
==4723== Leak size: 50 bytes
==4723== Leak memory address: 0x1009790
==4723==
==4723== Leak origin: main (test.c:3)
==4723== Leak size: 30 bytes
==4723== Leak memory address: 0x10096f0
==4723==
==4723== Program made 0 bad call(s) to free or realloc.
==4723==
==4723== HEAP SUMMARY:
==4723== Total memory requested: 120 bytes
==4723== Total memory freed: 40 bytes
==4723== Total leak: 80 bytes
```
