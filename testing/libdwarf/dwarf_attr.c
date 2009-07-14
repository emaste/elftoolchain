/*-
 * Copyright (c) 2007 John Birrell (jb@freebsd.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/lib/libdwarf/dwarf_attr.c,v 1.1 2008/05/22 02:14:23 jb Exp $
 */

#include <stdlib.h>
#include <string.h>
#include "_libdwarf.h"

int
dwarf_attr(Dwarf_Die die, Dwarf_Half attr, Dwarf_Attribute *atp,
    Dwarf_Error *err)
{
	Dwarf_Attribute at;
	int ret = DWARF_E_NONE;

	if (err == NULL)
		return DWARF_E_ERROR;

	if (die == NULL || atp == NULL) {
		DWARF_SET_ERROR(err, DWARF_E_ARGUMENT);
		return DWARF_E_ARGUMENT;
	}

	STAILQ_FOREACH(at, &die->die_attr, at_next)
		if (at->at_attrib == attr)
			break;

	*atp = at;

	if (at == NULL) {
		DWARF_SET_ERROR(err, DWARF_E_NO_ENTRY);
		ret = DWARF_E_NO_ENTRY;
	}

	return ret;
}

int
dwarf_attrdef_add(Dwarf_Abbrev ab, uint64_t attr, uint64_t form, uint64_t adoff,
    Dwarf_AttrDef *adp, Dwarf_Error *error)
{
	Dwarf_AttrDef ad;
	
	if (ab == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_ARGUMENT);
		return (DWARF_E_ARGUMENT);
	}

	if ((ad = malloc(sizeof(struct _Dwarf_AttrDef))) == NULL) {
		DWARF_SET_ERROR(error, DWARF_E_MEMORY);
		return (DWARF_E_MEMORY);
	}

	/* Initialise the attribute definition structure. */
	ad->ad_attrib	= attr;
	ad->ad_form	= form;
	ad->ad_offset	= adoff;

	/* Add the attribute definition to the list in the abbrev. */
	STAILQ_INSERT_TAIL(&ab->ab_attrdef, ad, ad_next);

	/* Increase number of attribute counter. */
	ab->ab_atnum++;

	if (adp != NULL)
		*adp = ad;

	return (DWARF_E_NONE);
}
