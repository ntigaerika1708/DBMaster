BINARY := vaultdb-agent
VERSION ?= 1.0.0
LDFLAGS := -s -w -X main.Version=$(VERSION)

.PHONY: build build-all install clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Binários para várias plataformas (linux/amd64, linux/arm64)
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)
	@test -f /etc/vaultdb-agent.env || install -m 0600 vaultdb-agent.env.example /etc/vaultdb-agent.env
	install -m 0644 vaultdb-agent.service /etc/systemd/system/vaultdb-agent.service
	systemctl daemon-reload
	@echo "Edite /etc/vaultdb-agent.env e: systemctl enable --now vaultdb-agent"

clean:
	rm -rf $(BINARY) dist/
