CLEANFILES= \
	    pandora.1 \
	    pandora.html
EXTRA_DIST= \
	    pandora.conf \
	    pandora.xml

if HAVE_XSLTPROC
XSLTPROC_FLAGS= \
		--nonet \
		--param funcsynopsis.style "'ansi'"

pandora.1: pandora.xml
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

pandora.html: pandora.xml
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

dist_man_MANS= \
	       pandora.1
endif # HAVE_XSLTPROC
