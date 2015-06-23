/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * Copyright (C) 2015 Naveen N. Rao, IBM Corporation
 */

#include "debug.h"
#include "symbol.h"
#include "probe-event.h"

#ifdef HAVE_LIBELF_SUPPORT
bool elf__needs_adjust_symbols(GElf_Ehdr ehdr)
{
	return ehdr.e_type == ET_EXEC ||
	       ehdr.e_type == ET_REL ||
	       ehdr.e_type == ET_DYN;
}

#if defined(_CALL_ELF) && _CALL_ELF == 2
void arch__elf_sym_adjust(GElf_Sym *sym)
{
	sym->st_value += PPC64_LOCAL_ENTRY_OFFSET(sym->st_other);
}
#endif
#endif

#if defined(_CALL_ELF) && _CALL_ELF == 2
bool arch__prefers_symtab(void)
{
	return true;
}
#endif
