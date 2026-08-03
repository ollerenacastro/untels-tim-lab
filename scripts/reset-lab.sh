#!/bin/bash
# Reinstalación limpia del TIM-Lab: BORRA TODOS LOS DATOS y vuelve a ingerir
# desde cero. Conserva la carpeta y el .env.
#
# Cuándo usarlo:
#   - El laboratorio quedó inservible y ./scripts/restart-lab.sh no lo arregla.
#   - Quieres partir de una plataforma vacía a propósito.
#
# Qué borra:  los cuatro volúmenes (esdata, redisdata, rabbitmqdata, miniodata).
#             Es decir, TODA la inteligencia ingerida.
# Qué NO borra: la carpeta del repositorio ni el .env.
#
# Por eso, después de correrlo, tu contraseña de admin y tus claves de feeds
# siguen siendo LAS MISMAS. No hay nada que apuntar ni que restaurar.
#
# Por qué conservar el .env es lo correcto y no un atajo:
#   Las credenciales internas (RabbitMQ, MinIO, token de OpenCTI) son un secreto
#   compartido entre el .env y los volúmenes. Al borrar los volúmenes, cada
#   servicio se reinicializa leyendo el .env, así que ambos lados vuelven a
#   coincidir. Si en cambio regeneraras el .env conservando los volúmenes,
#   RabbitMQ mantendría su contraseña vieja (solo aplica RABBITMQ_DEFAULT_PASS
#   con el directorio de datos vacío) y OpenCTI no podría autenticarse.
#
# Uso: ./scripts/reset-lab.sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [ ! -f .env ]; then
  echo "[reset-lab] No hay .env en $PROJECT_ROOT."
  echo "  Si nunca instalaste el lab, empieza por: ./scripts/setup-env.sh"
  exit 1
fi

# Respaldo del .env fuera del repositorio. No hace falta para este procedimiento
# —el .env no se toca— pero cuesta nada y cubre el caso de que más adelante
# decidas borrar la carpeta entera.
BACKUP="$HOME/tim-env-$(date +%F-%H%M).bak"
cp .env "$BACKUP"
chmod 600 "$BACKUP"
echo "[reset-lab] Copia de seguridad del .env en: $BACKUP"
echo ""

echo "[reset-lab] Se van a BORRAR estos volúmenes y todo lo que contienen:"
docker volume ls --filter "name=$(basename "$PROJECT_ROOT")_" --format '  - {{.Name}}' || true
echo ""
echo "  Perderás toda la inteligencia ingerida: ATT&CK, CVEs, indicadores."
echo "  Se vuelve a descargar sola, pero la primera carga tarda 20-40 minutos."
echo "  Tu contraseña de admin y tus claves de feeds NO cambian."
echo ""
printf "  Escribe BORRAR para continuar (cualquier otra cosa cancela): "
read -r CONFIRM
if [ "$CONFIRM" != "BORRAR" ]; then
  echo "[reset-lab] Cancelado. No se ha borrado nada."
  exit 0
fi

echo ""
echo "[reset-lab] Bajando stack y borrando volúmenes..."
# --profile otx incluye connector-alienvault aunque el perfil no esté activo en
# el .env; si su contenedor no existe, no pasa nada.
docker compose --profile otx down -v

echo "[reset-lab] Comprobando que no quedan volúmenes huérfanos..."
LEFT=$(docker volume ls --filter "name=$(basename "$PROJECT_ROOT")_" -q | wc -l)
if [ "$LEFT" -ne 0 ]; then
  echo "[reset-lab] AVISO: quedan $LEFT volúmenes. Revísalos con:"
  echo "  docker volume ls | grep $(basename "$PROJECT_ROOT")"
  exit 1
fi

echo "[reset-lab] Levantando el stack de cero..."
docker compose up -d --build

echo ""
echo "[reset-lab] Listo. La plataforma está vacía y los conectores ya ingiriendo."
echo "  Sigue el progreso con:  ./scripts/verify-platform.sh"
echo "  Entra en http://localhost:8080 con la MISMA contraseña de siempre."
