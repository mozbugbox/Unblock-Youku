TOP := $(dir $(lastword $(MAKEFILE_LIST)))
NODE = /usr/bin/nodejs

# If the first argument is "run", use rest targets as run arguments 
ifeq (run, $(firstword $(MAKECMDGOALS)))
	# use the rest as arguments for "run"
	RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
	# ...and turn them into do-nothing targets
	# $(eval $(RUN_ARGS):;	@:)
	# NO! We actually want to depend on the tested files
endif

JS_TARGET = dns-proxy.js \
	    reverse-sogou-proxy.js \
	    utils.js \


RAPYDSCRIPT = $(TOP)/node_modules/.bin/rapydscript 

all: $(JS_TARGET)

%.js: %.py
	$(NODE)  $(RAPYDSCRIPT) $< --screw-ie8 -p > $@

# To run the `test_main()` function of a javascript file, type
#     $ make run myfile.js
run: $(JS_TARGET)
	for k in ${RUN_ARGS}; do \
		base=`/usr/bin/basename $${k} .js`; \
		/bin/echo "Testing \"$${k}\" ..."; \
		$(NODE) -e "require('./$${base}').test_main()";\
	done

.PHONY: all run

# vim:fileencoding=utf-8:sw=8:tabstop=8
