BINARY_DIR = .bin
APP_NAME = toucan-calls

TARGET ?= linux
ARCH ?= amd64
DOCKER_IMAGE ?= parrothacker1/toucan-calls

CLIENT_SRC := ./cmd/client
SERVER_SRC := ./cmd/server

DEBUG_FLAGS = 
RELEASE_FLAGS = -ldflags="-s -w"

CLIENT_DEBUG_BIN = $(BINARY_DIR)/$(APP_NAME)-client-debug-$(TARGET)-$(ARCH)
CLIENT_RELEASE_BIN = $(BINARY_DIR)/$(APP_NAME)-client-release-$(TARGET)-$(ARCH)
SERVER_DEBUG_BIN = $(BINARY_DIR)/$(APP_NAME)-server-debug-$(TARGET)-$(ARCH)
SERVER_RELEASE_BIN = $(BINARY_DIR)/$(APP_NAME)-server-release-$(TARGET)-$(ARCH)


EXT := 
ifeq ($(TARGET),windows)
	EXT := .exe
endif


CLIENT_DEBUG_BIN := $(CLIENT_DEBUG_BIN)$(EXT)
CLIENT_RELEASE_BIN := $(CLIENT_RELEASE_BIN)$(EXT)
SERVER_DEBUG_BIN := $(SERVER_DEBUG_BIN)$(EXT)
SERVER_RELEASE_BIN := $(SERVER_RELEASE_BIN)$(EXT)

CLIENT_BIN := $(CLIENT_DEBUG_BIN)
SERVER_BIN := $(SERVER_DEBUG_BIN)
FLAGS := $(DEBUG_FLAGS)

BUILD ?= debug

ifeq ($(BUILD),release)
	CLIENT_BIN := $(CLIENT_RELEASE_BIN)
	SERVER_BIN := $(SERVER_RELEASE_BIN)
	FLAGS := $(RELEASE_FLAGS)
endif

.PHONY: all build-client build-server build-server-docker clean clean-image run-client run-server

setup:
	@echo "[X] Setting up dir"
	@mkdir -p $(BINARY_DIR)

build-client: setup
	@echo "[X] Building the client $(BUILD) binary"
	@CGO_ENABLED=0 GOOS=$(TARGET) GOARCH=$(ARCH) \
			 go build $(FLAGS) -o $(CLIENT_BIN) $(CLIENT_SRC) 
	@echo "[X] Done building the client $(BUILD) binary"

build-server: setup
	@echo "[X] Building the server $(BUILD) binary"
	@CGO_ENABLED=0 GOOS=$(TARGET) GOARCH=$(ARCH) \
			 go build $(FLAGS) -o $(SERVER_BIN) $(SERVER_SRC) 
	@echo "[X] Done building the server $(BUILD) binary"

build-server-docker:
	@echo "[X] Building the server docker image"
	@docker build -t $(DOCKER_IMAGE) -f ./Dockerfile . 
	@echo "[X] Done building server docker image with tag $(DOCKER_IMAGE)"

clean-image:
	@echo "[X] Removing the server docker image $(DOCKER_IMAGE)"
	@docker rmi $(DOCKER_IMAGE)
	@echo "[X] Done removing $(DOCKER_IMAGE)"

clean:
	@echo "[X] Removing all binaries from $(BINARY_DIR) dir"
	@rm -rf $(BINARY_DIR)

run-client: build-client
	@echo "[X] Running the client binary"
	@./$(CLIENT_BIN)

run-server: build-server 
	@echo "[X] Running the server binary"
	@./$(SERVER_BIN)

