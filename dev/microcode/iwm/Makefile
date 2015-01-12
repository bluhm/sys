all:	iwlwifi-7260-9.ucode

iwlwifi-7260-9.ucode: iwlwifi-7260-9.uu
	rm -f ${.TARGET}
	uudecode -o ${.TARGET} ${.CURDIR}/iwlwifi-7260-9.uu

clean:
	rm -f iwlwifi-7260-9.ucode

.include <bsd.prog.mk>
