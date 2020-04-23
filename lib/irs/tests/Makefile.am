include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBIRS_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBIRS_LIBS)

noinst_PROGRAMS = \
	resconf_test

TESTS = $(noinst_PROGRAMS)

unit-local: check
