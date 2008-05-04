/*-
 * Copyright (c) 2007,2008 Kai Wang
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/queue.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "elfcopy.h"

void
insert_to_strtab(struct section *t, const char *s)
{
	const char *r;
	char *b, *c;
	size_t len, slen;
	int append;

	if (t->sz == 0) {
		t->cap = 512;
		if ((t->buf = malloc(t->cap)) == NULL)
			err(EX_SOFTWARE, "malloc failed");
	}

	slen = strlen(s);
	append = 0;
	b = t->buf;
	for (c = b; c < b + t->sz;) {
		len = strlen(c);
		if (!append && len >= slen) {
			r = c + (len - slen);
			if (strcmp(r, s) == 0)
				return;
		} else if (len < slen && len != 0) {
			r = s + (slen - len);
			if (strcmp(c, r) == 0) {
				t->sz -= len + 1;
				memmove(c, c + len + 1, t->sz - (c - b));
				append = 1;
				continue;
			}
		}
		c += len + 1;
	}

	while (t->sz + slen + 1 >= t->cap) {
		t->cap *= 2;
		if ((t->buf = realloc(t->buf, t->cap)) == NULL)
			err(EX_SOFTWARE, "realloc failed");
	}
	b = t->buf;
	strncpy(&b[t->sz], s, slen);
	b[t->sz + slen] = '\0';
	t->sz += slen + 1;
}

int
lookup_string(struct section *t, const char *s)
{
	const char *b, *c, *r;
	size_t len, slen;

	slen = strlen(s);
	b = t->buf;
	for (c = b; c < b + t->sz;) {
		len = strlen(c);
		if (len >= slen) {
			r = c + (len - slen);
			if (strcmp(r, s) == 0)
				return (r - b);
		}
		c += len + 1;
	}

	return (-1);
}
