CLEANFILES= \
	    pandora.1 \
	    pandora.html
EXTRA_DIST= \
	    pandora.xml

pandorasharedir= $(datadir)/$(PACKAGE)
pandorashare_DATA= \
		   paludis

if HAVE_XSLTPROC
XSLTPROC_FLAGS= \
		--encoding "'UTF-8'" \
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
html_DATA= \
	   pandora.html

upload-html: pandora.html
	rsync --progress -avze ssh $< bach.exherbo.org:public_html/pandora/
.PHONY: upload-html
else
pandora.1:
	@echo "You don't have xsltproc installed!"
	exit 1
pandora.html:
	@echo "You don't have xsltproc installed!"
	exit 1
upload-html:
	@echo "Not uploading HTML documentation"
	exit 0
endif # HAVE_XSLTPROC
