# Everyday entry points. Needs the .NET 10 SDK and Docker; Ollama either natively or via `make ollama`.
MODEL ?= qwen2.5-coder:7b

.PHONY: build test run up down ollama image

build:            ## compile everything
	dotnet build

test:             ## run the suite; suites needing Docker or Ollama skip when they are absent
	dotnet test

run:              ## postgres in Docker, API on the host at http://localhost:5045/scalar
	docker compose up -d --wait postgres
	dotnet run --project src/Stigsmith.Api

up:               ## the whole stack in Docker at http://localhost:8080/scalar
	docker compose up --build

down:             ## stop and remove the compose stack (data volumes are kept)
	docker compose down

ollama:           ## run Ollama in Docker and pull the model
	docker compose up -d ollama
	docker compose exec ollama ollama pull $(MODEL)

image:            ## the container the validation loop applies remediation in; nothing validates until it exists
	docker image inspect stigsmith/validation:el8 >/dev/null 2>&1 || docker build -t stigsmith/validation:el8 docker/validation
