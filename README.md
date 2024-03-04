使用指南
========

untils.py的MAGIC记得修改
如果为下面这种，MAGIC = "CSET"
```
CSET            W8, EQ
ADD             X9, X9, #1234@PAGEOFF
LDR             X8, [X9,W8,UXTW#3]
BR              X8
```
如果为这种，MAGIC = "CSEL"
```
MOV             W12, #0xA8
MOV             W13, #0x48 ; 'H'
CSEL            X12, X13, X12, EQ
LDR             X11, [X11,X12]
ADD             X11, X11, X15
BR              X11
```
