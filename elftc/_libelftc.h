/*-
 * Copyright (c) 2009 Kai Wang
 * Copyright (c) 2007,2008 Hyogeol Lee <hyogeollee@gmail.com>
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

#ifndef	__LIBELFTC_H_
#define	__LIBELFTC_H_

#include <stdbool.h>

/* Target types. */
#define	ET_ELF		0x0001U
#define	ET_BINARY	0x0001U
#define	ET_SREC		0x0001U

struct _Elf_Target {
	const char	*et_name;	/* target name. */
	unsigned int	 et_type;	/* target type. */
	unsigned int	 et_byteorder;	/* elf target byteorder. */
	unsigned int	 et_elfclass;	/* elf target class (32/64bit). */
	unsigned int	 et_machine;	/* elf target arch. */
};

/** @brief Dynamic vector data for string. */
struct vector_str {
	/** Current size */
	size_t		size;
	/** Total capacity */
	size_t		capacity;
	/** String array */
	char		**container;
};

#define BUFFER_GROWFACTOR	1.618
#define VECTOR_DEF_CAPACITY	8

/** @brief Deallocate resource in vector_str. */
void	vector_str_dest(struct vector_str *);

/**
 * @brief Find string in vector_str.
 * @param v Destination vector.
 * @param o String to find.
 * @param l Length of the string.
 * @return -1 at failed, 0 at not found, 1 at found.
 */
int	vector_str_find(const struct vector_str *v, const char *o, size_t l);

/**
 * @brief Get new allocated flat string from vector.
 *
 * If l is not NULL, return length of the string.
 * @param v Destination vector.
 * @param l Length of the string.
 * @return NULL at failed or NUL terminated new allocated string.
 */
char	*vector_str_get_flat(const struct vector_str *v, size_t *l);

/**
 * @brief Initialize vector_str.
 * @return false at failed, true at success.
 */
bool	vector_str_init(struct vector_str *);

/**
 * @brief Remove last element in vector_str.
 * @return false at failed, true at success.
 */
bool	vector_str_pop(struct vector_str *);

/**
 * @brief Push back string to vector.
 * @return false at failed, true at success.
 */
bool	vector_str_push(struct vector_str *, const char *, size_t);

/**
 * @brief Push front org vector to det vector.
 * @return false at failed, true at success.
 */
bool	vector_str_push_vector_head(struct vector_str *dst,
	    struct vector_str *org);

/**
 * @brief Get new allocated flat string from vector between begin and end.
 *
 * If r_len is not NULL, string length will be returned.
 * @return NULL at failed or NUL terminated new allocated string.
 */
char	*vector_str_substr(const struct vector_str *v, size_t begin, size_t end,
	    size_t *r_len);

/**
 * @brief Decode the input string by IA-64 C++ ABI style.
 *
 * GNU GCC v3 use IA-64 standard ABI.
 * @return New allocated demangled string or NULL if failed.
 * @todo 1. Testing and more test case. 2. Code cleaning.
 */
char	*cpp_demangle_gnu3(const char *);

/**
 * @brief Test input string is mangled by IA-64 C++ ABI style.
 *
 * Test string heads with "_Z" or "_GLOBAL__I_".
 * @return Return 0 at false.
 */
bool	is_cpp_mangled_gnu3(const char *);

/**
 * @brief Decode the input string by the GNU 2 style.
 *
 * @return New allocated demangled string or NULL if failed.
 */
char *cpp_demangle_gnu2(const char *);

/**
 * @brief Test input string is encoded by the GNU 2 style.
 *
 * @return True if input string is encoded by the GNU 2 style.
 */
bool is_cpp_mangled_gnu2(const char *);

/**
 * @brief Decode the input string by the ARM style.
 *
 * @return New allocated demangled string or NULL if failed.
 */
char *cpp_demangle_ARM(const char *);

/**
 * @brief Test input string is encoded by the ARM style.
 *
 * @return True if input string is encoded by the ARM style.
 */
bool is_cpp_mangled_ARM(const char *);

#endif	/* __LIBELFTC_H */
