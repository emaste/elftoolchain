# $FreeBSD$

all: test

cpp_demangle.o: ../cpp_demangle.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c ../cpp_demangle.c -o cpp_demangle.o

vector_str.o: ../vector_str.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c ../vector_str.c -o vector_str.o

test_cpp_demangle.o: test_cpp_demangle.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c test_cpp_demangle.c -o test_cpp_demangle.o

test_cpp_demangle: cpp_demangle.o vector_str.o test_cpp_demangle.o
	$(CC) -o test_cpp_demangle cpp_demangle.o vector_str.o test_cpp_demangle.o

test: test_cpp_demangle
	@echo
	@echo "======================================"
	@echo " Testing IA-64 c++ ABI demangling ..."
	@echo "======================================"
	./test_cpp_demangle

clean:
	rm -f *.o *.core test_cpp_demangle
