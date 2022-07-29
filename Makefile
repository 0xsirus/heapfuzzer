all: heapfuzzer

heapfuzzer: heapfuzzer.c
	gcc -oheapfuzzer heapfuzzer.c -lpthread

clean:
	rm heapfuzzer
