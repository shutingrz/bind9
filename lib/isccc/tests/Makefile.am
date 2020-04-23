include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.tests

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBISCCC_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBISCCC_LIBS)

noinst_PROGRAMS =	\
	result_test

TESTS = $(noinst_PROGRAMS)

unit-local: check
