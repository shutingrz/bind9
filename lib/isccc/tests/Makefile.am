include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBISCCC_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBISCCC_LIBS)

check_PROGRAMS =	\
	result_test

TESTS = $(check_PROGRAMS)

if TESTBUILD
noinst_PROGRAMS=$(check_PROGRAMS)
endif TESTBUILD

unit-local: check
