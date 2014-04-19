TOP := $(dir $(lastword $(MAKEFILE_LIST)))
NODE = /usr/bin/nodejs

JS_TARGET = dns-proxy.js
RAPYDSCRIPT = $(TOP)/node_modules/.bin/rapydscript 

all: $(JS_TARGET)

%.js: %.py
	$(NODE)  $(RAPYDSCRIPT) $< --screw-ie8 -p > $@

test: dns-proxy.js
	$(NODE) dns-proxy.js

.PHONY: all test
