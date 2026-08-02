# TIM-Lab — Threat Intelligence Management (versión de clase)

Stack **slim** de un sistema TIM real, construido sobre [OpenCTI](https://www.opencti.io/),
diseñado para correr dentro de la VM Kali de 8 GB que ya usas en el curso.

Sin módulos LLM, sin GPU. Lo que queda es el núcleo de un TIM: un **knowledge graph
STIX 2.1** poblado automáticamente con **MITRE ATT&CK**, **CISA KEV** (CVEs realmente
explotadas) e **IOCs vivos** de feeds públicos (URLhaus + Feodo Tracker).

---

## ¿Qué es esto y qué NO es?

| | Versión full (investigación) | **TIM-Lab (esta, clase)** |
|--|--|--|
| OpenCTI + knowledge graph | ✅ | ✅ |
| MITRE ATT&CK automático | ✅ | ✅ |
| CISA KEV | ✅ | ✅ |
| Feeds IOC (URLhaus, Feodo) | ✅ | ✅ |
| Extracción IA de PDFs (LLM) | ✅ | ❌ cortado (necesita GPU) |
| Búsqueda semántica (embeddings) | ✅ | ❌ cortado |
| Briefings PDF (LLM) | ✅ | ❌ cortado |
| Dashboard SOC custom + Kibana | ✅ | ❌ (se usa la UI de OpenCTI) |
| RAM necesaria | ~14 GB + GPU | **~6.5 GB, sin GPU** |

Sigue siendo un TIM: **ingiere → normaliza (STIX 2.1) → correlaciona → permite investigar**.

---

## Requisitos

- VM **Kali Linux** con **8 GB RAM** y **4 vCPUs** (ver guía de acondicionamiento abajo).
- **Docker** + **Docker Compose v2** (Kali 2025.x ya los trae: `docker --version`).
- **~15 GB** de disco libre para imágenes y datos.
- Conexión a internet (solo la primera vez, para descargar imágenes y ATT&CK).

---

## Parte 0 — Acondicionar la VM Kali (una sola vez)

> Estos pasos se hacen en el **host** (donde corre VirtualBox), con la **VM apagada**.
> El objetivo: darle a Kali 8 GB de RAM, 4 CPUs, y un **segundo disco de 25 GB**
> dedicado a Docker (para no llenar el disco del sistema).

### 0.1 — RAM y CPU (GUI de VirtualBox)

VM apagada → **Configuración → Sistema**:
- **Placa base → Memoria base: 8192 MB**
- **Procesador: 4 CPUs**

### 0.2 — Segundo disco de 25 GB para Docker

En la GUI: **Configuración → Almacenamiento → Controlador SATA → Agregar disco duro
→ Crear → VDI → Reservado dinámicamente → 25 GB**.

> ⚠️ **Verificación crítica dentro de Kali antes de formatear.**
> Arranca Kali y corre `lsblk`. El disco a formatear es el que **NO tiene particiones
> ni punto de montaje** (el nuevo, vacío). Las letras `sda`/`sdb` **pueden salir
> intercambiadas** — nunca formatees el disco que tiene `/` montado.

```bash
# 1. Identificar el disco NUEVO (sin particiones hijas ni MOUNTPOINTS)
lsblk

# 2. Formatear SOLO el disco nuevo — reemplaza sdX por el correcto (p.ej. sda, sdb, sdc)
sudo mkfs.ext4 /dev/sdX

# 3. Detener Docker antes de mover su directorio
sudo systemctl stop docker docker.socket

# 4. Mover datos previos y montar el disco nuevo en /var/lib/docker
sudo mv /var/lib/docker /var/lib/docker.old 2>/dev/null; sudo mkdir /var/lib/docker
UUID=$(sudo blkid -s UUID -o value /dev/sdX)
echo "UUID=$UUID /var/lib/docker ext4 defaults 0 2" | sudo tee -a /etc/fstab
sudo systemctl daemon-reload
sudo mount /var/lib/docker

# 5. Reiniciar Docker y confirmar
sudo systemctl start docker
docker info | grep "Docker Root Dir"     # debe decir /var/lib/docker
df -h /var/lib/docker                     # debe mostrar ~25G
```

Usar **UUID** en `/etc/fstab` (no `/dev/sdX`) evita que un reordenamiento de discos
entre reinicios rompa el arranque.

---

## Parte 1 — Levantar el TIM

```bash
# 1. Clonar el repo dentro de Kali
git clone https://github.com/ollerenacastro/untels-tim-lab.git
cd untels-tim-lab

# 2. Generar credenciales (.env con UUIDs y passwords aleatorios)
./scripts/setup-env.sh
#    ⚠️ GUARDA la password de admin que imprime — no se puede recuperar.

# 3. Levantar todo (un solo comando)
docker compose up -d --build

# 4. Esperar a que OpenCTI importe MITRE ATT&CK (~5-15 min según hardware)
./scripts/verify-platform.sh
#    Termina cuando hay 100+ objetos ATT&CK importados.
```

Cuando `verify-platform.sh` diga **"Platform ready"**, abre en el navegador de Kali:

```
http://localhost:8080
```

Login con `admin@tim.local` y la password que guardaste en el paso 2.

> **⚠️ Al retomar el lab (tras suspender o apagar la VM):** NO uses
> `docker compose up -d` ni `--force-recreate`. Usa **`./scripts/restart-lab.sh`**.
> Al reanudar la VM los contenedores vuelven sin respetar el orden de arranque:
> OpenCTI sube antes que Elasticsearch, crashea y toma una IP nueva → el puerto
> `8080` del host queda "muerto" (aunque `docker compose ps` diga *healthy*).
> `restart-lab.sh` hace `down` + `up` limpio y reordena por healthcheck. Los datos
> persisten (viven en volúmenes; `down` sin `-v` no los borra).

---

## Parte 2 — Comandos útiles

```bash
# Reinicio LIMPIO — úsalo al empezar clase o tras suspender/apagar la VM
./scripts/restart-lab.sh

# Ver estado de todos los servicios
docker compose ps

# Ver logs de un servicio (p.ej. el conector de ATT&CK)
docker compose logs -f connector-mitre

# Cuántos IOCs vivos trajo el feed-orchestrator
curl -s http://localhost:8001/feeds/status | python3 -m json.tool

# Exportar todos los IOCs como bundle STIX 2.1
curl -s http://localhost:8001/feeds/export/stix | python3 -c "import sys,json; print(len(json.load(sys.stdin)['objects']), 'objetos STIX')"

# Apagar el TIM (conserva los datos)
docker compose down

# Apagar y BORRAR todos los datos (empezar de cero)
docker compose down -v
```

---

## Arquitectura — los 9 módulos del stack

Un solo `docker compose up` levanta **9 contenedores** repartidos en cuatro capas.

### Capa 1 — Almacenamiento y mensajería (dependencias de OpenCTI)

Ninguno es OpenCTI; son la infraestructura que OpenCTI necesita para existir.

| Servicio | Rol real | RAM |
|----------|----------|-----|
| `elasticsearch` | **Almacén principal.** Aquí viven de verdad todas las entidades STIX (actores, malware, TTPs, CVEs, IOCs). Resuelve toda búsqueda de la UI. | 2 GB |
| `redis` | **Memoria de trabajo.** Locks de concurrencia, caché de sesión y el *event stream* que consumen los managers internos. | 512 MB |
| `rabbitmq` | **Cola de mensajes.** Los conectores no escriben en OpenCTI: publican bundles STIX aquí. Desacopla ingesta de procesamiento. | 512 MB |
| `minio` | **Almacén de archivos** (S3 local): reportes PDF, imágenes, adjuntos. | 256 MB |

### Capa 2 — Núcleo del TIM

| Servicio | Rol real | Puerto | RAM |
|----------|----------|--------|-----|
| `opencti` | Plataforma: **API GraphQL + UI web**. El cerebro — consultas, reglas de inferencia y managers internos (History, Notification, Rule, Playbook, Activity, Sync). | `127.0.0.1:8080` | 1.5 GB |
| `worker` | **Obrero de ingesta.** Consume bundles de RabbitMQ y los escribe vía API. Si muere, la data se acumula en la cola pero nada entra al grafo. | interno | 512 MB |

### Capa 3 — Conectores (ingesta de inteligencia)

| Servicio | Qué aporta | Cadencia | RAM |
|----------|------------|----------|-----|
| `connector-mitre` | **MITRE ATT&CK completo**: `intrusion-set` (actores), `malware`, `tool`, `attack-pattern` (TTPs), `course-of-action`, `campaign`. ~1500 patrones de ataque. | 7 días | 512 MB |
| `connector-cisa-kev` | **CISA Known Exploited Vulnerabilities**: CVEs con explotación confirmada en el mundo real. Sin API key. | 7 días | 256 MB |
| `feed-orchestrator` | **Servicio custom del curso** (único con `build:` en vez de `image:`). IOCs vivos de URLhaus + Feodo; con API keys en `.env` añade OTX, MalwareBazaar y ThreatFox. API propia en `127.0.0.1:8001`. | 1–6 h | 512 MB |

### Capa 4 — Infraestructura Docker

- **Red `tim-network`** (bridge aislada): los contenedores se hablan por nombre de servicio
  (`http://opencti:8080`, `redis://redis:6379`), no por IP.
- **Volúmenes persistentes**: `esdata`, `redisdata`, `rabbitmqdata`, `miniodata`.
  Por esto `docker compose down` **sin** `-v` nunca pierde datos.

### Flujo de un dato, de la fuente al analista

```
  Fuente externa          Conector          Cola         Worker        Núcleo        Almacén
 ────────────────      ──────────────    ──────────    ─────────    ──────────   ──────────────
  MITRE ATT&CK   ──►  connector-mitre ──┐
  CISA KEV       ──►  connector-cisa  ──┼─► RabbitMQ ──► worker ──► OpenCTI ──┬─► Elasticsearch
  URLhaus/Feodo  ──►  feed-orchestr.  ──┘   (bundles               (API)      ├─► Redis
                                            STIX 2.1)                         └─► MinIO
                                                                     │
                                                                     ▼
                                                             UI :8080 (analista)
```

Todo entra normalizado a **STIX 2.1** — heterogéneo por fuera, un solo idioma por dentro:
**ingiere → normaliza → correlaciona → investiga**.

> ⚠️ **Presupuesto de memoria:** la suma de `mem_limit` ronda **6.5 GB** sobre una VM de
> **8 GB**. El margen es estrecho a propósito: si un servicio se reinicia solo, sospecha de
> memoria antes que de nada (`docker stats`). Elasticsearch y Redis son los más ajustados.

---

## Solución de problemas

| Síntoma | Causa probable | Fix |
|--------|----------------|-----|
| `:8080` muerto tras suspender/reiniciar la VM (aunque `ps` diga *healthy*) | NAT del host apunta a la IP vieja de OpenCTI; contenedores reanudados sin orden | **`./scripts/restart-lab.sh`** (no `up -d` ni `--force-recreate` sueltos) |
| `curl 127.0.0.1:8080` → HTTP 000 pero contenedor *healthy* | Igual que arriba (proxy stale) | `./scripts/restart-lab.sh` |
| worker/connectors: `Connection refused opencti:8080` en bucle | OpenCTI reiniciándose; se auto-cura al subir | Espera; si persiste, `./scripts/restart-lab.sh` |
| OpenCTI no carga en `:8080` | Aún arrancando (tarda ~1-2 min tras `up`) | Espera; `docker compose logs -f opencti` |
| `verify-platform.sh` se queda en 0 objetos | ATT&CK aún importando | Normal los primeros 5-15 min |
| Logs de OpenCTI llenos de `MISCONF Redis ... unable to persist to disk` / `Redis transaction error` | Redis excede su `mem_limit`: el `fork()` del snapshot RDB cruza el límite del cgroup y el kernel lo mata en bucle. La UI carga (HTTP 200) pero **las escrituras están rotas** | 1) `sudo sysctl vm.overcommit_memory=1` (+ añadirlo a `/etc/sysctl.conf`) · 2) subir `mem_limit` de `redis` en `docker-compose.yml` · 3) `docker compose up -d redis` y luego `./scripts/restart-lab.sh` |
| `docker compose logs redis` muestra `Redis is starting` una y otra vez | Mismo caso: OOM-kill en cada `bgsave`. Compara `RDB memory usage when created` con el `mem_limit` — si el dataset se acerca al límite, no cabe el fork | Sube el `mem_limit` de `redis` por encima del dataset + margen (512m cubre ~266 MB de datos) |
| Elasticsearch muere / reinicia | Poca RAM | Cierra apps del host; confirma VM = 8 GB |
| `max virtual memory areas vm.max_map_count too low` | Límite del kernel | `sudo sysctl -w vm.max_map_count=262144` |
| Todo lento | VM con < 8 GB o < 4 CPU | Revisa Parte 0 |

---

Curso de Ciberseguridad — UNTELS 2026.
