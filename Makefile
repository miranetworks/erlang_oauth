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



#Docker targets
dbuild: docker/Dockerfile.template
	cd docker; ./build $(if $(nocache),nocache)

dcibuild:
	cd docker; ./run "./script/cibuild"

dtest:
	cd docker; ./run_test "make test"

dclean:
	cd docker; ./run "make clean"

drun:
	cd docker; ./run "make run"


