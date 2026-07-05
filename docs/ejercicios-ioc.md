# Ejercicios de Investigación de IoCs — TIM-Lab

> Prerrequisito: el TIM levantado y `verify-platform.sh` en verde (100+ objetos ATT&CK).
> Trabajas en la UI de OpenCTI: `http://localhost:8080`.

Estos ejercicios usan datos **reales** ya presentes en tu instancia:
- **MITRE ATT&CK** completo: ~650 técnicas, ~725 malware, ~155 grupos (actores), ~50 campañas.
- **CISA KEV**: ~530 CVEs realmente explotadas en el mundo real.
- **IOCs vivos** de URLhaus: ~2300 indicadores (URLs/IPs maliciosas actuales).

Cada ejercicio entrega un **producto** concreto que el alumno documenta.

---

## Conceptos antes de empezar

| Término | Definición operativa |
|--------|----------------------|
| **IoC** (Indicator of Compromise) | Dato observable que evidencia actividad maliciosa: IP, dominio, hash, URL. Responde *"¿qué busco en mis logs?"* |
| **TTP** (Tactic, Technique, Procedure) | Comportamiento del adversario (MITRE ATT&CK: `Txxxx`). Responde *"¿cómo opera?"* |
| **Intrusion Set** (actor) | Grupo de actividad atribuida a un adversario (OilRig, APT39...). |
| **Relationship** | Arista del knowledge graph: `usa`, `atribuido-a`, `apunta-a`, `indica`. El pivoteo vive aquí. |

> **Pirámide del Dolor:** bloquear un hash duele poco al atacante (lo cambia fácil);
> bloquear sus TTPs le duele mucho (rediseñar su operación). Por eso un TIM correlaciona
> IoCs → TTPs → actor, no solo lista IoCs sueltos.

---

## Ejercicio 1 — Trazabilidad de actor: OilRig (APT34)

> **Continuidad con tema04.** OilRig es el adversario que emulaste en el tema04. Aquí lo
> ves desde el lado del *analista de inteligencia*, no del atacante.

**Objetivo:** partir de un actor y reconstruir su perfil operativo completo navegando el grafo.

**Pasos en OpenCTI:**
1. Barra de búsqueda → escribe `OilRig` → abre el intrusion-set.
2. Pestaña **Overview**: anota sus **aliases** (verás `APT34`, `Helix Kitten`, `Crambus`,
   `Earth Simnavaz`...). *Pregunta: ¿por qué un mismo grupo tiene tantos nombres?*
3. Pestaña **Knowledge → Techniques**: lista las técnicas ATT&CK que usa. Compáralas con
   las del tema04. *¿Aparece T1071.001 (C2 sobre HTTP)? ¿T1059 (intérprete de comandos)?*
4. Pestaña **Knowledge → Malware**: identifica su arsenal (busca herramientas como
   `Helminth`, `QUADAGENT`, `BONDUPDATER`).
5. Pestaña **Knowledge → Victimology / Targeting**: ¿qué sectores y regiones ataca?

**Producto a entregar:** ficha de una página de OilRig con:
- 3 alias y por qué existen (pista: distintos vendors nombran independientemente).
- 5 TTPs principales con su táctica ATT&CK.
- 2 familias de malware propias.
- Sectores/países objetivo.
- **Una recomendación defensiva** por cada uno de 3 TTPs (¿qué detectarías/bloquearías?).

---

## Ejercicio 2 — Investigar un IoC vivo de URLhaus

**Objetivo:** tomar un indicador real recién ingerido y decidir si es accionable.

**Pasos en OpenCTI:**
1. Menú lateral **Observations → Indicators**. Ordena por **Score** (descendente).
2. Elige un indicador con score alto (p.ej. una URL `http://<ip>/...`). Ábrelo.
3. Anota: **patrón STIX**, **score de confianza**, **valid_from / valid_until**, **labels**.
4. Pestaña **Knowledge**: ¿está relacionado con algún malware o campaña? ¿O es un IoC
   "huérfano" (sin contexto)?
5. Extrae la **IP o dominio** del patrón. *¿Qué harías con este dato en un firewall/SIEM?*

**Producto a entregar:** mini-reporte de triaje del IoC:
- Valor del IoC, tipo, score, y qué significa ese score (fórmula de confianza del feed).
- ¿Accionable ya, o requiere enriquecimiento? Justifica.
- Regla de detección conceptual: *"alertar si un host interno resuelve/conecta a `<IoC>`"*.
- Discute la **caducidad**: ¿por qué un IoC de URL "expira" y un TTP no?

---

## Ejercicio 3 — Pivoteo inverso desde un TTP

**Objetivo:** partir de un comportamiento (no de un IoC) y llegar a los actores — el
razonamiento de "threat hunting".

**Pasos en OpenCTI:**
1. Busca la técnica **T1071.001** (*Application Layer Protocol: Web Protocols*).
2. Ábrela → pestaña **Knowledge → Intrusion Sets**: lista **todos los grupos** que usan
   esta técnica. *¿Cuántos hay? ¿Está OilRig?*
3. Elige 2 grupos distintos y compara: ¿comparten malware? ¿mismos sectores objetivo?
4. Pestaña **Knowledge → Malware** de la técnica: ¿qué familias implementan C2 por HTTP?

**Producto a entregar:**
- Lista de ≥5 actores que usan T1071.001.
- Argumenta por qué esta técnica es tan común (pista: el tráfico HTTP se camufla con el
  tráfico legítimo — *defense evasion*).
- Propón **una regla de caza**: ¿qué patrón en logs de proxy/DNS delataría C2 sobre HTTP
  aunque no conozcas la IP exacta? (Aquí es donde el TTP vence al IoC.)

---

## Ejercicio 4 (opcional) — Vulnerabilidad explotada (CISA KEV)

**Objetivo:** conectar el mundo de vulnerabilidades con el de amenazas.

**Pasos en OpenCTI:**
1. Menú **Arsenal → Vulnerabilities**. Filtra/busca una CVE conocida
   (p.ej. `CVE-2021-44228` — Log4Shell, si está en el catálogo KEV).
2. Anota CVSS, descripción, y si tiene relaciones con malware/actores.
3. *¿Por qué CISA mantiene una lista separada de CVEs "explotadas conocidas" en vez de
   usar solo CVSS?* (Pista: CVSS mide severidad teórica; KEV mide explotación real.)

**Producto:** párrafo argumentando cómo priorizarías parches usando KEV vs. solo CVSS.

---

## Rúbrica de evaluación (sugerida)

| Criterio | Peso |
|---------|------|
| Uso correcto de la navegación del grafo (pivoteo real, no copiar-pegar) | 30% |
| Distinción IoC vs TTP aplicada correctamente | 25% |
| Recomendaciones defensivas concretas y realistas | 25% |
| Claridad del reporte (un analista SOC lo entendería) | 20% |

---

Curso de Ciberseguridad — UNTELS 2026.
