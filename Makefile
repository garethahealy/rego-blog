.PHONY: build
build: README.html

.PHONY: clean
clean:
	rm -f README.html

README.html: README.md
	pandoc -o $@ $<