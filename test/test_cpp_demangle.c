/*-
 * Copyright (c) 2007 Hyogeol Lee <hyogeollee@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cpp_demangle.h"

static int		test_cpp_demangle_ia64(const char *, const char *);

static int
test_cpp_demangle_ia64(const char *org, const char *dst)
{
        int rtn;
	char *rst;

	if ((rst = cpp_demangle_ia64(org)) == NULL) {
		printf("%s [Fail]\n", org);

		return (1);
	}

        if ((rtn = strcmp(rst, dst)) != 0)
                printf("%s -> %s : %s : %s", org, rst, dst, "[Failed]\n");

        free(rst);

	return (rtn);
}

/*
 * test cpp demangling codes.
 *
 * example from http://www.codesourcery.com/cxx-abi/abi-examples.html#mangling
 */
int
main(void)
{
        int rtn;

        rtn = 0;

        /* from mangling example */
	rtn |= test_cpp_demangle_ia64("_Z1fv", "f(void)");
	rtn |= test_cpp_demangle_ia64("_Z1fi", "f(int)");
        rtn |= test_cpp_demangle_ia64("_Z3foo3bar", "foo(bar)");
        rtn |= test_cpp_demangle_ia64("_Zrm1XS_", "operator%(X, X)");
        rtn |= test_cpp_demangle_ia64("_ZplR1XS0_", "operator+(X&, X&)");
        rtn |= test_cpp_demangle_ia64("_ZlsRK1XS1_",
            "operator<<(X const&, X const&)");
        rtn |= test_cpp_demangle_ia64("_ZN3FooIA4_iE3barE",
            "Foo<int[4]>::bar");
        rtn |= test_cpp_demangle_ia64("_Z1fIiEvi", "void f<int>(int)");
        rtn |= test_cpp_demangle_ia64("_Z5firstI3DuoEvS0_",
            "void first<Duo>(Duo)");
        rtn |= test_cpp_demangle_ia64("_Z5firstI3DuoEvT_",
            "void first<Duo>(Duo)");
        rtn |= test_cpp_demangle_ia64("_Z3fooIiPFidEiEvv",
            "void foo<int, int(*)(double), int>(void)");
        rtn |= test_cpp_demangle_ia64("_ZN1N1fE", "N::f");
        rtn |= test_cpp_demangle_ia64("_ZN6System5Sound4beepEv",
            "System::Sound::beep(void)");
        rtn |= test_cpp_demangle_ia64("_ZN5Arena5levelE", "Arena::level");
        rtn |= test_cpp_demangle_ia64("_ZN5StackIiiE5levelE",
            "Stack<int, int>::level");
        rtn |= test_cpp_demangle_ia64("_Z1fI1XEvPVN1AIT_E1TE",
            "void f<X>(A<X>::T volatile*)");
        rtn |= test_cpp_demangle_ia64("_ZngILi42EEvN1AIXplT_Li2EEE1TE",
            "void operator-<42>(A<J+2>::T)");
        rtn |= test_cpp_demangle_ia64("_Z4makeI7FactoryiET_IT0_Ev",
            "Factory<int> make<Factory, int>(void)");
        rtn |= test_cpp_demangle_ia64("_Z3foo5Hello5WorldS0_S_",
            "foo(Hello, World, World, Hello)");
        rtn |= test_cpp_demangle_ia64("_Z3fooPM2ABi", "foo(int AB::**)");
        rtn |= test_cpp_demangle_ia64("_ZlsRSoRKSs",
            "operator<<(std::ostream&, std::string const&)");
        rtn |= test_cpp_demangle_ia64("_ZTI7a_class",
            "typeinfo for (a_class)");

        /* from #5.1 mangling example */
        rtn |= test_cpp_demangle_ia64("_ZSt5state", "std::state");
        rtn |= test_cpp_demangle_ia64("_ZNSt3_In4wardE", "std::_In::ward");

	return (rtn);
}
