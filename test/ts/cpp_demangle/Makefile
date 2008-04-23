TET_ROOT?=	/usr/tet
LIBDIR=		$(TET_ROOT)/lib/tet3
INCDIR=		$(TET_ROOT)/inc/tet3
CC=		c99
CFLAGS=		-I$(INCDIR)

vector_str.o:	../../../vector_str.c
	$(CC) -o vector_str.o -c ../../../vector_str.c

cpp_demangle.o: ../../../cpp_demangle.c vector_str.o
	$(CC) -o cpp_demangle.o -c ../../../cpp_demangle.c

cpp_demangle-tc: cpp_demangle-tc.c cpp_demangle.o $(INCDIR)/tet_api.h
	$(CC) $(CFLAGS) -o cpp_demangle-tc cpp_demangle-tc.c vector_str.o \
		cpp_demangle.o $(LIBDIR)/tcm.o \
		$(LIBDIR)/libapi.a

clean:
	rm -f *.o cpp_demangle-tc

lint:
	lint $(CFLAGS) cpp_demangle-tc.c -ltcm
