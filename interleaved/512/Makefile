CC = armclang
CFLAGS = -O3 -Wall -Wextra -march=armv8-a+sve

main: main.c ntt.c ntt.h function7.s function7.h function6.s function6.h function5.s function5.h function4.s function4.h function3.s function3.h function2.s function2.h function1.s function1.h function0.s function0.h precomp.c reduce.c reduce.h params.h
	$(CC) $(CFLAGS) main.c ntt.c function7.s function6.s function5.s function4.s function3.s function2.s function1.s function0.s precomp.c reduce.c -o $@

.PHONY: clean

clean:
	-rm main
