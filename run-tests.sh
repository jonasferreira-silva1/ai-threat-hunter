#!/bin/bash
# =============================================================
# Script de execução dos testes via Docker
# Uso: ./run-tests.sh
# =============================================================

echo "Construindo imagem de testes..."
docker build -f docker/Dockerfile.test -t threat-hunter-tests .

echo ""
echo "Rodando testes..."
echo "============================================================="
docker run --rm threat-hunter-tests "$@"
