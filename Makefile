flags := -Wall -I.
ldflags :=

.Phony: clean

all: dnscli

dnscli: dnscli.o
	cc $(flags) $^ -o $@ $(ldflags)

dnscli.o: dnscli.c
	cc $(flags) -c $<

clean:
	rm -f *.o dnscli
