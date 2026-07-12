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

## Mapa de servicios

| Servicio | Rol | Puerto |
|----------|-----|--------|
| `opencti` | Knowledge graph + UI — **aquí trabajas** | `localhost:8080` |
| `feed-orchestrator` | Ingesta IOCs vivos (URLhaus + Feodo) | `localhost:8001` |
| `connector-mitre` | Importa MITRE ATT&CK (actores, malware, TTPs) | interno |
| `connector-cisa-kev` | Importa CVEs explotadas (CISA KEV) | interno |
| `elasticsearch` · `redis` · `rabbitmq` · `minio` · `worker` | Motor interno de OpenCTI | interno |

---

## Solución de problemas

| Síntoma | Causa probable | Fix |
|--------|----------------|-----|
| `:8080` muerto tras suspender/reiniciar la VM (aunque `ps` diga *healthy*) | NAT del host apunta a la IP vieja de OpenCTI; contenedores reanudados sin orden | **`./scripts/restart-lab.sh`** (no `up -d` ni `--force-recreate` sueltos) |
| `curl 127.0.0.1:8080` → HTTP 000 pero contenedor *healthy* | Igual que arriba (proxy stale) | `./scripts/restart-lab.sh` |
| worker/connectors: `Connection refused opencti:8080` en bucle | OpenCTI reiniciándose; se auto-cura al subir | Espera; si persiste, `./scripts/restart-lab.sh` |
| OpenCTI no carga en `:8080` | Aún arrancando (tarda ~1-2 min tras `up`) | Espera; `docker compose logs -f opencti` |
| `verify-platform.sh` se queda en 0 objetos | ATT&CK aún importando | Normal los primeros 5-15 min |
| Elasticsearch muere / reinicia | Poca RAM | Cierra apps del host; confirma VM = 8 GB |
| `max virtual memory areas vm.max_map_count too low` | Límite del kernel | `sudo sysctl -w vm.max_map_count=262144` |
| Todo lento | VM con < 8 GB o < 4 CPU | Revisa Parte 0 |

---

Curso de Ciberseguridad — UNTELS 2026.
