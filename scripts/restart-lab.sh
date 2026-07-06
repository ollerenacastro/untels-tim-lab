#!/bin/bash
# Arranque limpio del TIM-Lab. Úsalo SIEMPRE al empezar la clase o tras
# suspender/apagar la VM Kali.
#
# Por qué down+up y no `up -d`:
#   Al reanudar la VM, los contenedores vuelven con restart:unless-stopped
#   PERO sin respetar el orden depends_on (solo aplica en `up`). opencti
#   arranca antes que ES/Redis, crashea, toma IP nueva -> el NAT del host
#   para el puerto 8080 queda stale (navegador muerto) y los connectors
#   entran en crash-loop. `down` limpia red+IPs, `up` reordena por healthcheck.
#   Los datos NO se pierden: viven en volúmenes nombrados (esdata, etc.).
#
# Uso: ./scripts/restart-lab.sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "[restart-lab] Bajando stack (red + contenedores, NO volúmenes)..."
docker compose down            # ponytail: SIN -v. -v borraría los datos.

echo "[restart-lab] Levantando en orden (depends_on + healthchecks)..."
docker compose up -d

echo "[restart-lab] Esperando a que OpenCTI responda en 127.0.0.1:8080..."
for i in $(seq 1 60); do       # hasta ~5 min (arranque caliente real ~2 min)
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080 || echo 000)
  if [ "$code" = "200" ] || [ "$code" = "302" ]; then
    echo "[restart-lab] OpenCTI arriba (HTTP $code). Abre http://127.0.0.1:8080 en Kali."
    exit 0
  fi
  printf '  intento %s/60 -> HTTP %s\r' "$i" "$code"
  sleep 5
done

echo ""
echo "[restart-lab] AVISO: OpenCTI no respondió 200 en 5 min."
echo "  Revisa: docker compose ps   y   docker compose logs opencti"
exit 1
