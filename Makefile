IMAGE  := ratpak-build
DOCKER := docker

DOCKER_RUN := $(DOCKER) run --rm \
        -v $(CURDIR):/work -w /work \
        --user $$(id -u):$$(id -g) \
        $(IMAGE)

CAPS := cap_bpf,cap_perfmon+ep

.PHONY: image build generate clean shell tidy setcap

image:
	$(DOCKER) build -t $(IMAGE) .

generate: image
	$(DOCKER_RUN) go generate ./...

build: image
	$(DOCKER_RUN) sh -c "go generate ./... && go build -o bin/ratpak ."

tidy: image
	$(DOCKER_RUN) go mod tidy

clean:
	rm -rf bin/

shell: image
	$(DOCKER) run --rm -it -v $(CURDIR):/work -w /work --user $$(id -u):$$(id -g) $(IMAGE) sh

# Grant the BPF/perfmon caps on bin/ratpak so `observe` (and the future
# daemon) can run as the regular user. Requires root via doas — separate
# target from `build` so the privileged step is explicit.
setcap:
	@test -x bin/ratpak || { echo "bin/ratpak missing — run 'make build' first" >&2; exit 1; }
	doas setcap $(CAPS) bin/ratpak
	@getcap bin/ratpak
