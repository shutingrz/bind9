include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.docs

MANPAGES_RST =				\
	arpaname.rst			\
	ddns-confgen.rst		\
	delv.rst			\
	dig.rst				\
	dnssec-cds.rst			\
	dnssec-dsfromkey.rst		\
	dnssec-importkey.rst		\
	dnssec-keyfromlabel.rst		\
	dnssec-keygen.rst		\
	dnssec-revoke.rst		\
	dnssec-settime.rst		\
	dnssec-signzone.rst		\
	dnssec-verify.rst		\
	dnstap-read.rst			\
	filter-aaaa.rst			\
	host.rst			\
	mdig.rst			\
	named-checkconf.rst		\
	named-checkzone.rst		\
	named-journalprint.rst		\
	named-nzd2nzf.rst		\
	named-rrchecker.rst		\
	named.conf.rst			\
	named.rst			\
	nsec3hash.rst			\
	nslookup.rst			\
	nsupdate.rst			\
	pkcs11-destroy.rst		\
	pkcs11-keygen.rst		\
	pkcs11-list.rst			\
	pkcs11-tokens.rst		\
	rndc-confgen.rst		\
	rndc.conf.rst			\
	rndc.rst

man_MANS =				\
	arpaname.1			\
	delv.1				\
	dig.1				\
	dnstap-read.1			\
	host.1				\
	mdig.1				\
	named-rrchecker.1		\
	nslookup.1			\
	nsupdate.1			\
	named.conf.5			\
	rndc.conf.5			\
	ddns-confgen.8			\
	dnssec-cds.8			\
	dnssec-dsfromkey.8		\
	dnssec-importkey.8		\
	dnssec-keyfromlabel.8		\
	dnssec-keygen.8			\
	dnssec-revoke.8			\
	dnssec-settime.8		\
	dnssec-signzone.8		\
	dnssec-verify.8			\
	filter-aaaa.8			\
	named-checkconf.8		\
	named-checkzone.8		\
	named-journalprint.8		\
	named-nzd2nzf.8			\
	named.8				\
	nsec3hash.8			\
	rndc-confgen.8			\
	rndc.8

if HAVE_PKCS11
man_MANS +=				\
	pkcs11-destroy.8		\
	pkcs11-keygen.8			\
	pkcs11-list.8			\
	pkcs11-tokens.8
endif HAVE_PKCS11

MANPAGES_IN =				\
	$(man_MANS:=in)

EXTRA_DIST =				\
	conf.py				\
	$(MANPAGES_RST)			\
	$(MANPAGES_IN)

MAINTAINERCLEANFILES =			\
	$(MANPAGES_IN)

CLEANFILES =				\
	$(man_MANS)			\
	manpages.stamp

#
# Build rules for pre-generated manpages
#

man_SUBST =							\
	$(AM_V_SED)$(SED)					\
	  -e 's,[@]PACKAGE_VERSION@,$(PACKAGE_VERSION),'	\
	  -e 's,[@]RELEASE_DATE@,$(RELEASE_DATE),'		\
	  $(srcdir)/$@in >$@

.1in.1:
	$(man_SUBST)

.5in.5:
	$(man_SUBST)

.8in.8:
	$(man_SUBST)

.NOTPARALLEL: man
man: Makefile $(man_MANS)

clean-local::
	-rm -rf $(SPHINXBUILDDIR)

#
# Build rules for generating pre-generated manpages
#

if HAVE_SPHINX_BUILD
#
# See https://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html
#
manpages.stamp: $(MANPAGES_RST)
	@rm -f manpages.tmp
	@touch manpages.tmp
	$(AM_V_SPHINX)$(SPHINX_BUILD) -b man -d $(SPHINXBUILDDIR)/doctrees $(man_SPHINXOPTS) $(SPHINXBUILDDIR)/man
	for f in $(SPHINXBUILDDIR)/man/*; do \
	  cp -a "$$f" "$(srcdir)/$$(basename $$f)in"; \
	done
	@mv -f manpages.tmp $@

$(MANPAGES_IN): manpages.stamp
## Recover from the removal of $@
        @dry=; for f in x $$MAKEFLAGS; do \
          case $$f in \
            *=*|--*);; \
            *n*) dry=:;; \
          esac; \
        done; \
        if test -f $@; then :; else \
          $$dry trap 'rm -rf manpages.lock manpages.stamp' 1 2 13 15; \
          if $$dry mkdir manpages.lock 2>/dev/null; then \
## This code is being executed by the first process.
            $$dry rm -f manpages.stamp; \
            $(MAKE) $(AM_MAKEFLAGS) manpages.stamp; \
            $$dry rmdir manpages.lock; \
          else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
            while test -d manpages.lock && test -z "$$dry"; do \
              sleep 1; \
            done; \
## Succeed if and only if the first process succeeded.
            $$dry test -f manpages.stamp; exit $$?; \
          fi; \
        fi
endif HAVE_SPHINX_BUILD

maintainerclean-local:
	-$(RM)
