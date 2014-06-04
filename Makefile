.PHONY: deps test

all: deps
	@./rebar compile

deps:
	@./rebar get-deps

test: all
	@./rebar eunit skip_deps=true

clean:
	@./rebar clean

distclean: clean
	@./rebar delete-deps
