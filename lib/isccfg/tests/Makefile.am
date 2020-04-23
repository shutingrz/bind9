include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBISCCFG_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBISCCFG_LIBS)

noinst_PROGRAMS = \
	parser_test

TESTS = $(noinst_PROGRAMS)

unit-local: check
