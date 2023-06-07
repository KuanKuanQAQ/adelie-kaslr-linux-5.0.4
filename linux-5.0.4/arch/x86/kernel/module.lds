SECTIONS {
	/* Movable section */
	.got (NOLOAD) : { BYTE(0) } /* Non-randomizable GOT */
	.got.rand (NOLOAD) : { BYTE(0) } /* Randomizable GOT */
	.plt (NOLOAD) : { BYTE(0) } /* Non-randomizable PLT */
	.plt.rand (NOLOAD) : { BYTE(0) } /* Randomizable PLT */
	/* Immovable (fixed) section */
	.fixed.got (NOLOAD) : { BYTE(0) } /* Non-randomizable GOT */
	.fixed.got.rand (NOLOAD) : { BYTE(0) } /* Randomizable GOT */
	.fixed.plt (NOLOAD) : { BYTE(0) } /* Non-randomizable PLT */
	.fixed.plt.rand (NOLOAD) : { BYTE(0) } /* Randomizable PLT */
}
