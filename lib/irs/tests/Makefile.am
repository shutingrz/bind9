include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBIRS_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBIRS_LIBS)

check_PROGRAMS = \
	resconf_test

TESTS = $(check_PROGRAMS)

if TESTBUILD
noinst_PROGRAMS=$(check_PROGRAMS)
endif TESTBUILD

unit-local: check
