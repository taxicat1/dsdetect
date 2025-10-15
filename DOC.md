# Identifying versions of DS Protect in games

This document details exactly what `dsdetect.py` is doing.

## Where is DS Protect?

Most commonly, DS Protect is in its own dedicated overlay. Only rarely does a game include it in its static region or package other code along with it in its overlay. Many games do not use overlays at all, *except* for storing DS Protect in overlay 0. Otherwise, you will have to search the static region and overlays for some signature of DS Protect.

## How can DS Protect be identified?

Every single version of DS Protect (except for the unknown 1.00/2) includes these bytes in a `.rodata` region:

`FF F6 40 FF FF CE 00 00`

These are bit-flipped zero-padded bytes of the default MAC address that was used by No$GBA at the time. This was never updated across the versions of DS Protect, nor was its encoding or storage location ever changed.

### Version identification via garbage data

In versions 1.23 onward, six words of unique garbage data reside in a `.rodata` region (usually nearby the MAC address):

```
e2ed720b  ;  6 words of garbage data
ef69d1b1    
2ec32a41    
1aa3e665    
e9e1c153    
e49e8d9c    

ff40f6ff  ;  MAC address
0000ceff    
```

In versions 2.00 and above, two pointers are found between the MAC address and the garbage data:

```
08b76046  ;  6 words of garbage data
e4177f2f    
5ab21c99    
ea2af4b1    
e0fe885a    
e202fc9e    

021d97c4  ;  <some pointers>
021d9888    

ff40f6ff  ;  MAC address
0000ceff    
```

In either case, the garbage data can be used to positively identify the DS Protect version:

| Version | Garbage words |
| --- | --- |
|   1.23    | `ebaa0113 e4064ec7 ef013596 e5212f83 e7ee335b e83b197c`  |
|   1.23z   | `ebaa0114 40064eb7 5f013696 e5211f83 e7ef335b e84b197c`  |
|   1.25    | `ebb6df66 e42f6211 ef56b5aa e5b903fd e7d29154 e859697c`  |
|   1.26    | `eb8fbc31 e4ec10cf ef73e592 e59a0b7e e78cb309 e87f3ed1`  |
|   1.27    | `e8dffe17 e43df0de 2ae8335c 0ac09826 e7a838dc e891a6fc`  |
|   1.28    | `e2ed720b ef69d1b1 2ec32a41 1aa3e665 e9e1c153 e49e8d9c`  |
|   2.00    | `0819ff33 e4a1ef1c 5a85a2b3 ea0d2a0f e0d6bd78 e29d9377`  |
|   2.00s   | `0849ea8b e33b6243 53b2d501 e6847168 ebd886d7 ee3c09c0`  |
|   2.01    | `08d5310e e41bdb46 5a3d9627 eaf8fc79 e016c9e7 e2eb8130`  |
|   2.01s   | `08637dd1 e3618cb3 5356f520 e6b110ca eb4c1e5c eed91028`  |
|   2.03    | `08b76046 e4177f2f 5ab21c99 ea2af4b1 e0fe885a e202fc9e`  |
|   2.03s   | `08b76046 e4177f2f 5ab21c99 ea2af4b1 e0fe885a e2029efc`  |
|   2.05    | `08a27510 e47ab3c3 5a289302 eaa6cac8 e00d75d5 e2d2fe01`  |
|   2.05s   | `08a27510 e47ab3c3 5a289302 eaa6cac8 e00d75d5 e2d2fe00`  |

### Version identification via encryption keys

Versions prior to 1.23 do not have garbage data. They still have the MAC address data, but preceding it is regular instructions:

```
ebfffcdd  ;  <some instructions>
e8bd0001    
e59d0004    
e28dd088    
e8bd8ff8    

ff40f6ff  ;  MAC address
0000ceff    
```

(Or, if other code is packaged together with DS Protect in the same overlay, random other data)

In this case, the next easiest method is to search the instructions for the encryption keys. Encryption keys are embedded inline with the function code, and appear like this in disassemblies:

```
e08f0100  ;  regular instructions
ebfffbff    
e8bd03ff    
ea000000  ;  EA000000 -- jump over next instruction
eb00093f  ;  EB00XXXX -- 16-bit encryption key XXXX
e59e0219  ;  encrypted instructions start
e242889c    
e5d24f09    
...
02825765    
ea01637b  ;  encrypted instructions end
eb00093f  ;  EB00XXXX -- same encryption key XXXX again
e92d0001  ;  regular instructions continue
e1a0000f    
e2400014    
```

Versions 1.06 to 1.10 use eleven different encryption keys, while versions 1.20 and 1.22 use eighteen different encryption keys, and the unknown version 1.00/2 only uses seven. Note that these versions did not have any protection against deadstripping, so if the given game did not utilize all of the DS Protect functions, some of the functions (and corresponding keys) may be missing.

The encryption keys can be used to identify the DS Protect version:

| Version | Keys |
| --- | --- |
|  1.00/2  | `002A` `4824` `18BF` `6785` `2CD7` `4AE2` `3D6D` |
|  1.05  |  `4276` `7A4A` `70C2` `476E` `1961` `5514` `3304` `350E` `2E8E` `09A1` `0E5E` |
|  1.06  |  `3530` `3089` `5FDF` `0D2C` `350E` `48F8` `59B5` `3481` `65C5` `12F0` `76BB` |
|  1.08  |  `0317` `1DFA` `4979` `1476` `4544` `4EF9` `292E` `1186` `1CC4` `72A8` `7CD4` |
|  1.10  |  `66F2` `2F11` `1CFC` `4F55` `1729` `6981` `61AE` `2578` `275E` `0351` `2E37` |
|  1.20  |  `0F57` `0D8B` `0314` `7EF6` `2F0C` `480C` `03F9` `735A` `53EF` `1D7A` `58A8` `129E` `496B` `4165` `6506` `7566` `38AD` `1F1A` |
|  1.22  |  `3B74` `67FA` `239B` `298C` `37EE` `0C13` `31F6` `38CA` `5C87` `2393` `66D9` `0639` `1530` `66F1` `63ED` `0BAE` `1800` `093F` |

### Version identification via encrypted instructions

For practical purposes, strings of encrypted instructions can be used as identifiers. As every version of DS Protect uses differing encryption keys, none of them share a significant overlap of ciphertext.

In `dsdetect.py`, the end of the range of encrypted instructions for the ROM reading utility function (`ROMUtil_Read` in [dsprot](https://github.com/taxicat1/dsprot/)), including the encryption key at the end, was chosen as the range to use.

However, in theory, a given game could call only the MAC/owner and dummy DS Protect functions, causing the ROM reading function to be deadstripped out, and this detection method to fail. In practice, not using the ROM reading detection methods would make DS Protect virtually inert, so this was likely never done.

These are the instruction ranges chosen for these versions:

| Version | Encrypted instructions |
| --- | --- |
|  1.00/2  | `e3527270 bafe77fc e59e0989 e1c2f9af ea018a51 eb004ae2` |
|  1.05  | `bafe0f18 e59caf7a e2861884 e1c5da54 ea018a6b eb0070c2` |
|  1.06  | `bafe9b10 e59cfa77 e2862a71 e1c54e3d ea01879d eb005fdf` |
|  1.08  | `bafe4040 e59c2300 e2852226 e1c5cbe8 ea01612f eb004979` |
|  1.10  | `bafe29a2 e59cc95b e285d70a e1c5442c ea01fd7e eb001cfc` |
|  1.20  | `e3580f00 bafe7df8 e284dff9 e1c2059d ea014de4 eb002f0c` |
|  1.22  | `e3581567 bafee339 e284dad2 e1c27622 ea017231 eb0037ee` |
