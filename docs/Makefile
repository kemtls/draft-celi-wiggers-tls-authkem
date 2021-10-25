all: authkem-abridged.html


%.html: %.md
	pandoc -f markdown+autolink_bare_uris --standalone --toc $< -o $@
