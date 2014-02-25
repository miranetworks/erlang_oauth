ERL ?= erl
APP := erlang_oauth

.PHONY: deps test

all: deps
	@./rebar compile

deps:
	@./rebar get-deps

test: all
	@./rebar eunit skip_deps=true

run: all
	@./start.sh

clean:
	@./rebar clean

distclean: clean
	@./rebar delete-deps

docs:
	@erl -noshell -run edoc_run application '$(APP)' '"."' '[]'
