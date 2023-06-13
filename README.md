# LR35902 Assembler and Disassembler

Just an experimental assembler and disassembler for the Sharp LR35902
CPU. This is the CPU used in the Gameboys.

The assembler outputs flat binaries at the moment.

## Build

Just run make, damnit.

## Usage

```console
$ ./lr35902as input.S output.bin
$ ./lr35902dis input.bin
```

## License

See LICENSE file. The opcodes.json file is taken from
https://github.com/lmmendes/game-boy-opcodes (MIT License).
