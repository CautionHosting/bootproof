ifdef NOCACHE
NO_CACHE := --no-cache
endif

.DEFAULT_GOAL :=
.PHONY: default
default: out/bootproof

## Primary targets

out/bootproof: Containerfile $(shell git ls-files crates Cargo.toml Cargo.lock) | out
	docker build \
		--progress=plain \
		--output type=local,rewrite-timestamp=true,dest=out \
		$(NO_CACHE) \
		-f Containerfile \
		.

## Development Targets

out/dev-shell.digest: Containerfile | out
	docker build --target dev -f Containerfile -q . > $@

.PHONY: shell
shell: out/dev-shell.digest
	docker run \
		--env TPM2TOOLS_TCTI="swtpm:port=2321" \
		--volume .:/home/user \
		--workdir /home/user \
		-it $(shell cat $<) /bin/sh -c " \
		mkdir -p /tmp/swtpm && \
		swtpm socket \
			--tpmstate dir=/tmp/swtpm \
			--tpm2 \
			--server type=tcp,port=2321 \
			--ctrl type=tcp,port=2322 \
			--flags not-need-init,startup-clear & \
		sh \
	"

.PHONY: clean
clean:
	rm -rf out

out:
	mkdir -p $@
