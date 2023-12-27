APP_VERSION = $(shell cat VERSION)
COMMIT_ID = $(shell git describe --dirty --long --always)
BUILD_TIME = $(shell date "+%F %T %Z")

ifeq ($(DEBUG), 1)
GCFLAGS = all=-N -l
endif

BUILDINFO_PKG = github.com/didi/yarc/internal/buildinfo

LDFLAGS = -X '$(BUILDINFO_PKG).Version=$(APP_VERSION)' \
          -X '$(BUILDINFO_PKG).CommitID=$(COMMIT_ID)' \
          -X '$(BUILDINFO_PKG).BuildTime=$(BUILD_TIME)'

all: yarc

yarc: cmd/yarc recorder
	@echo "> build yarc..."
	@echo "Version: $(APP_VERSION)"
	go build -gcflags="$(GCFLAGS)" -ldflags="$(LDFLAGS)" -o $@ ./cmd/yarc
	@echo "> done"
	@echo ""

recorder:
	$(MAKE) -C internal/recorder

clean:
	-$(MAKE) -C internal/recorder clean
	-$(RM) yarc

.PHONY: all recorder clean
