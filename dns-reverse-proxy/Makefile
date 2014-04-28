TOP := $(dir $(lastword $(MAKEFILE_LIST)))
# node binary is renamed to nodejs on Debian
NODE = $(shell which nodejs || which node)

# locate rapydscript file
# pass NPM_PATH to make will override rapydscript bin path
RAPYDSCRIPT = rapydscript
NPM = $(shell which npm)
ifndef NPM_PATH
	NPM_PATH = $(shell ${NPM} bin)
endif

ifeq (,$(wildcard ${NPM_PATH}))
	NPM_PATH =
	RAPYDSCRIPT := $(shell which ${RAPYDSCRIPT})
else
	RAPYDSCRIPT := ${NPM_PATH}/${RAPYDSCRIPT}
endif

# If the first argument is "run", use rest targets as run arguments 
ifeq (run, $(firstword $(MAKECMDGOALS)))
	# use the rest as arguments for "run"
	RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
	# ...and turn them into do-nothing targets
	# $(eval $(RUN_ARGS):;	@:)
	# NO! We actually want to depend on the tested files
endif

JS_TARGET = dns-proxy.js \
	    droxy.js \
	    reverse-sogou-proxy.js \
	    utils.js \

all: $(JS_TARGET)

%.js: %.py
ifeq (, $(wildcard ${RAPYDSCRIPT}))
	$(error please install 'rapydscript' by `npm install rapydscript`)
endif
	${NODE} ${RAPYDSCRIPT} $< --screw-ie8 -p > $@

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
