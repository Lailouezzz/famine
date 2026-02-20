ENTRY(_start)

SECTIONS {
	. = 0x0;
	HIDDEN(stub_begin = .);
	.text : {
		*(.stub.init)
		. = ALIGN(32);
		*(.text)
		. = ALIGN(32);
		*(.rodata*)
		. = ALIGN(32);
		*(.data)
		. = ALIGN(32);
		*(.data.rel*)
		. = ALIGN(32);
		*(.bss)
		. = ALIGN(16);
		*(.stub.data)
		HIDDEN(stub_end = .);
	}
	ASSERT(stub_end == ., "Padding after stub data")
	/DISCARD/ : {
		*(*)
		*(.note*)
		*(.comment)
		*(.eh_frame*)
		*(.got*)
		*(.plt*)
		*(.rela*)
		*(.dynsym)
		*(.dynstr)
		*(.hash)
		*(.gnu.hash)
		*(.shstrtab)
		*(.symtab)
		*(.strtab)
	}
}
