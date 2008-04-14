/*-
 * Copyright (c) 2008 Hyogeol Lee <hyogeollee@gmail.com>
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

#ifndef	GUARD_VECTOR_STR_H
#define	GUARD_VECTOR_STR_H

#include <stdlib.h>

#define VECTOR_DEF_CAPACITY	12
#define BUFFER_GROWFACTOR	1.61

struct vector_str {
	size_t		size, capacity;
	char		**container;
};

void	vector_str_dest(struct vector_str *);
int	vector_str_find(struct vector_str *, const char *, size_t);
char	*vector_str_get_flat(struct vector_str *, size_t *);
int	vector_str_init(struct vector_str *);
int	vector_str_pop(struct vector_str *);
char	*vector_str_substr(struct vector_str *, size_t, size_t, size_t *);
int	vector_str_push(struct vector_str *, const char *, size_t);
int	vector_str_push_vector_head(struct vector_str *, struct vector_str*);

#endif /* !GUARD_VECTOR_STR_H */
