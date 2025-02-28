# Nome do comando de execução
RUN_CMD = go run $(SERVER_DIR)/main.go

# Diretório do servidor
SERVER_DIR = cmd/server

# Nome do executável
APP_NAME = kaizen-auth-server

# Regra padrão para rodar o servidor
.PHONY: run
run:
	$(RUN_CMD)

commit:
	@if [ -z "$(message)" ]; then \
		echo "Erro: é necessário fornecer uma mensagem de commit."; \
		exit 1; \
	fi
	@git add . && git commit -m "$(message)" && git push

# Regra para limpar (não é obrigatória mas pode ser útil)
.PHONY: clean
clean:
    # Aqui você pode adicionar comandos para limpar build artifacts, logs, etc.
	@echo "Clean is not implemented yet."

# Regra para instalar dependências (opcional)
.PHONY: deps
deps:
	go mod tidy

# Regra para testar (opcional)
.PHONY: test
test:
	go test ./...

# Regra para build (opcional)
.PHONY: build
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o $(APP_NAME) $(SERVER_DIR)/main.go

# Regra para rodar o build
.PHONY: start
start: build
	./$(APP_NAME)