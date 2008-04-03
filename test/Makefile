# $FreeBSD$

ELFCOPY=	../elfcopy
ECPDIR!=	dirname ${ELFCOPY}
STRIP:=		${ECPDIR}/strip
MCS:=		${ECPDIR}/mcs

test: ${ELFCOPY} ${STRIP} ${MCS}
	/bin/sh run.sh

clean: ecpclean stripclean mcsclean

${ELFCOPY}:
	cd ${ECPDIR} && ${MAKE}

${STRIP}: ${ELFCOPY}
	ln -f ${ELFCOPY} ${STRIP}

${MCS}: ${ELFCOPY}
	ln -f ${ELFCOPY} ${MCS}

ecpclean:
	cd ${ECPDIR} && ${MAKE} clean

stripclean:
	rm -f ${STRIP}

mcsclean:
	rm -f ${MCS}
