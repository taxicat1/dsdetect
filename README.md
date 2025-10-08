# dsdetect

Automatically detect the location and version of DS Protect in a Nintendo DS ROM file.

Examples:

```
$ py dsdetect.py pokeheartgold.us.nds

Game: [IPKE] POKEMON HG

DS Protect found @ overlay 123
Version: 1.23
Address: 0225F020
```

```
$ py dsdetect.py POKEMON_W2_IRDO01_00.nds

Game: [IRDO] POKEMON W2

DS Protect found @ overlay 165
Version: 2.05 Instant
Address: 021A3138

DS Protect found @ overlay 337
Version: 2.05
Address: 0217F640
```

See [dsprot](https://github.com/taxicat1/dsprot/) for DS Protect decompilations.
