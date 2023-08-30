.PHONY: clean run all

all: rom.gb

rom.gb rom.lst rom.sym: rom.S main.S
	../lr35902as -s rom.sym -l rom.lst -o rom.gb rom.S

clean:
	rm -f rom.gb rom.lst rom.sym

run: rom.gb
	sameboy -s rom.gb
