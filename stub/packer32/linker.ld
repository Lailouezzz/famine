ENTRY(_start)

SECTIONS {
	. = 0x0;
	HIDDEN(packer_begin = .);
	.text : {
		*(.packer.init)
		. = ALIGN(32);
		*(.text)
		. = ALIGN(32);
		*(.text.*)
		. = ALIGN(32);
		*(.rodata*)
		. = ALIGN(32);
		*(.data)
		. = ALIGN(32);
		*(.data.rel*)
		. = ALIGN(4);
		*(.got.plt)
		. = ALIGN(32);
		*(.got)
		. = ALIGN(32);
		*(.bss)
		. = ALIGN(16);
		*(.packer.data)
		HIDDEN(packer_data_end = .);
	}
	ASSERT(packer_data_end == ., "Padding after packer data")
	/DISCARD/ : {
		*(*)
		*(.note*)
		*(.comment)
		*(.eh_frame*)
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
