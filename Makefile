IMAGE  := ratpak-build
DOCKER := docker

DOCKER_RUN := $(DOCKER) run --rm \
        -v $(CURDIR):/work -w /work \
        --user $$(id -u):$$(id -g) \
        $(IMAGE)

.PHONY: image build generate clean shell tidy

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
