#!/bin/bash
# Genera .env desde .env.example con UUIDs y contraseñas automáticas.
# Uso: ./scripts/setup-env.sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Idempotente: no sobrescribe un .env existente.
if [ -f "$PROJECT_ROOT/.env" ]; then
  echo "[setup-env] .env ya existe. Bórralo para regenerar."
  exit 0
fi

cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
chmod 600 "$PROJECT_ROOT/.env"

echo "[setup-env] Generando UUIDs y contraseñas..."

_gen_uuid() {
  if command -v uuidgen > /dev/null 2>&1; then uuidgen; else python3 -c "import uuid; print(uuid.uuid4())"; fi
}
OPENCTI_TOKEN=$(_gen_uuid)
CONNECTOR_MITRE_UUID=$(_gen_uuid)
CONNECTOR_CISA_KEV_UUID=$(_gen_uuid)

# Contraseñas alfanuméricas — evitan problemas de quoting con sed.
ADMIN_PASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 20)
RABBITMQ_PASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 24)
MINIO_SECRET=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 24)

_set_var() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$PROJECT_ROOT/.env"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$PROJECT_ROOT/.env"
  else
    echo "${key}=${val}" >> "$PROJECT_ROOT/.env"
  fi
}
_set_var OPENCTI_ADMIN_TOKEN "$OPENCTI_TOKEN"
_set_var OPENCTI_ADMIN_PASSWORD "$ADMIN_PASS"
_set_var CONNECTOR_MITRE_ID "$CONNECTOR_MITRE_UUID"
_set_var CONNECTOR_CISA_KEV_ID "$CONNECTOR_CISA_KEV_UUID"
_set_var RABBITMQ_PASSWORD "$RABBITMQ_PASS"
_set_var MINIO_SECRET_KEY "$MINIO_SECRET"

echo "[setup-env] .env generado (chmod 600)."
echo ""
echo "  === CREDENCIALES DE ACCESO A OpenCTI (guárdalas) ==="
echo "  URL:      http://localhost:8080"
echo "  Usuario:  admin@tim.local"
echo "  Password: ${ADMIN_PASS}"
echo "  ===================================================="
echo ""
echo "[setup-env] Siguiente paso: docker compose up -d"
