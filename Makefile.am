include $(top_srcdir)/Makefile.top

SUBDIRS = . libltdl lib doc bin

BUILT_SOURCES = bind.keys.h
CLEANFILES = bind.keys.h

bind.keys.h: bind.keys Makefile
	${PERL} ${top_srcdir}/util/bindkeys.pl < ${top_srcdir}/bind.keys > $@

dist_sysconf_DATA = bind.keys

.PHONY: doc

README: README.md
	${PANDOC} --email-obfuscation=none -s --metadata title="README" -f markdown-smart -t html README.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

HISTORY: HISTORY.md
	${PANDOC} --email-obfuscation=none -s --metadata title="HISTORY" -f markdown-smart -t html HISTORY.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

OPTIONS: OPTIONS.md
	${PANDOC} --email-obfuscation=none -s --metadata title="OPTIONS" -f markdown-smart -t html OPTIONS.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

CONTRIBUTING: CONTRIBUTING.md
	${PANDOC} --email-obfuscation=none -s --metadata title="CONTRIBUTING" -f markdown-smart -t html CONTRIBUTING.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

PLATFORMS: PLATFORMS.md
	${PANDOC} --email-obfuscation=none -s --metadata title="PLATFORMS" -f markdown-smart -t html PLATFORMS.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

CODE_OF_CONDUCT: CODE_OF_CONDUCT.md
	${PANDOC} --email-obfuscation=none -s --metadata title="CODE OF CONDUCT" -f markdown-smart -t html CODE_OF_CONDUCT.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

EXTRA_DIST = 			\
	util/bindkeys.pl	\
	contrib			\
	CHANGES			\
	CODE_OF_CONDUCT		\
	CODE_OF_CONDUCT.md	\
	CONTRIBUTING		\
	CONTRIBUTING.md		\
	HISTORY			\
	HISTORY.md		\
	OPTIONS			\
	OPTIONS.md		\
	PLATFORMS		\
	PLATFORMS.md		\
	README			\
	README.md
