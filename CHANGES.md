# Cambios realizados al CAI original (v0.5.10)

Este documento detalla **todos los ficheros creados y modificados** respecto al repositorio original de CAI (`cai-repo/`), explicando **qué se cambió, por qué y qué función cumple cada modificación**.

El CAI original es un framework de agentes de IA para ciberseguridad. Las modificaciones tienen dos objetivos principales:

1. **Crear patrones multi-agente orquestados** (Red Team y Bug Bounty) donde un agente central coordina a varios especialistas, cada uno con su propio modelo LLM.
2. **Mejorar la robustez con modelos locales (Ollama)** — los modelos pequeños (~8B-72B parámetros) no usan function calling de forma fiable, así que se añadieron mecanismos de detección y recuperación.
3. **Ampliar el arsenal de explotación web** — servidores MCP (Burp Suite y OWASP ZAP) y toolkits nativos (`@function_tool`) para XSS, JWT, LFI y file upload, que encapsulan la lógica correcta y evitan que el modelo la reescriba a mano.

> **Nota de mantenimiento**: la parte final del documento está organizada por iteraciones cronológicas (iteración 3, 4, servidores MCP, herramientas web, robustez del runtime). Cada sección referencia los hashes de commit relevantes entre paréntesis.

---

## Tabla de contenidos

- [Ficheros nuevos](#ficheros-nuevos)
  - [Agentes Red Team](#agentes-red-team-6-ficheros)
  - [Agentes Bug Bounty](#agentes-bug-bounty-6-ficheros)
  - [Prompts Red Team](#prompts-red-team-6-ficheros)
  - [Prompts Bug Bounty](#prompts-bug-bounty-6-ficheros)
  - [Patrones de orquestación](#patrones-de-orquestación-4-ficheros)
  - [Sistema de Tool Profiles](#sistema-de-tool-profiles-15-ficheros)
  - [Servidor MCP de Burp Suite](#servidor-mcp-de-burp-suite-2-ficheros)
  - [Infraestructura de testing](#infraestructura-de-testing-13-ficheros)
- [Ficheros modificados](#ficheros-modificados)
  - [SDK Core](#sdk-core)
  - [Agentes y Factory](#agentes-y-factory)
  - [CLI](#cli)
  - [Herramientas](#herramientas)
  - [Prompts existentes](#prompts-existentes-modificados)
- [Fichero eliminado](#fichero-eliminado)
- [Variables de entorno nuevas](#variables-de-entorno-nuevas)
- [Servidor MCP de OWASP ZAP](#servidor-mcp-de-owasp-zap-alternativa-libre-a-burp-suite)
- [Herramientas web nativas de explotación](#herramientas-web-nativas-de-explotación)
- [Robustez del runtime y de los prompts](#robustez-del-runtime-y-de-los-prompts-iteración-final)
- [Documentación añadida](#documentación-añadida-ficheros-nuevos)
- [Resumen de impacto](#resumen-de-impacto)

---

## Ficheros nuevos

### Agentes Red Team (6 ficheros)

Cada agente es un módulo Python independiente que define un `Agent` con su system prompt, herramientas y nombre. Los 6 forman un equipo coordinado en topología hub-and-spoke (el Orchestrator delega y todos devuelven el control al Orchestrator).

| Fichero | Función |
|---------|---------|
| `src/cai/agents/orchestrator.py` | **Coordinador central** — recibe el objetivo del pentest, decide qué especialista debe actuar en cada momento, y mantiene el estado general del ataque. No ejecuta comandos directamente. |
| `src/cai/agents/recon.py` | **Reconocimiento** — escaneo de puertos (nmap), enumeración de servicios, fuzzing de directorios (gobuster/ffuf), y descubrimiento de la superficie de ataque. |
| `src/cai/agents/strategy.py` | **Estrategia** — analiza los hallazgos del reconocimiento y genera un plan de ataque priorizado. NO tiene herramientas de ejecución, solo razona y escribe el plan. |
| `src/cai/agents/exploitation.py` | **Explotación** — ejecuta los ataques planificados: SQLi (sqlmap), fuerza bruta (hydra), exploits conocidos, etc. |
| `src/cai/agents/privesc.py` | **Escalada de privilegios** — tras obtener acceso inicial, busca vectores para escalar a root: SUID binaries, kernel exploits, cron jobs mal configurados, etc. |
| `src/cai/agents/report.py` | **Informe** — recopila toda la evidencia y genera un informe de pentest estructurado en Markdown con severidades, remediaciones y timeline. |

### Agentes Bug Bounty (6 ficheros)

Equipo análogo al Red Team pero enfocado a programas de Bug Bounty (respeto al scope, reporte responsable, sin escalada de privilegios).

| Fichero | Función |
|---------|---------|
| `src/cai/agents/bb_coordinator.py` | Coordinador del workflow de bug bounty |
| `src/cai/agents/bb_recon.py` | Reconocimiento de scope y activos |
| `src/cai/agents/bb_web_analyzer.py` | Análisis de aplicaciones web |
| `src/cai/agents/bb_vulnhunter.py` | Búsqueda activa de vulnerabilidades |
| `src/cai/agents/bb_exploit.py` | Verificación/explotación controlada |
| `src/cai/agents/bb_report.py` | Generación de reportes para plataformas de bug bounty |

### Prompts Red Team (6 ficheros)

Cada agente Red Team tiene su system prompt en Markdown que define sus instrucciones, herramientas disponibles, formato de salida y ejemplos de tool calls.

| Fichero | Contenido destacado |
|---------|---------------------|
| `src/cai/prompts/system_orchestrator_agent.md` | Instrucciones para coordinar el equipo, criterios para delegar a cada especialista |
| `src/cai/prompts/system_recon_agent.md` | Metodología de reconocimiento, ejemplos de nmap/gobuster/ffuf, integración con Burp Suite MCP |
| `src/cai/prompts/system_strategy_agent.md` | Formato de análisis (BREAKDOWN → VULNERABILITY ASSESSMENT → ATTACK PLAN → FALLBACK). **Aviso explícito**: "You do NOT have generic_linux_command" para evitar que escriba comandos |
| `src/cai/prompts/system_exploitation_agent.md` | Metodología de explotación, ejemplos de sqlmap/hydra, integración con Burp Suite MCP |
| `src/cai/prompts/system_privesc_agent.md` | Checklist de escalada: SUID, capabilities, cron, kernel, sudo -l |
| `src/cai/prompts/system_report_agent.md` | Plantilla de informe: Executive Summary, Findings con severidad, Timeline, Remediaciones |

### Prompts Bug Bounty (6 ficheros)

| Fichero | Contenido destacado |
|---------|---------------------|
| `src/cai/prompts/system_bb_coordinator_agent.md` | Workflow de BB, respeto al scope |
| `src/cai/prompts/system_bb_recon_agent.md` | Enumeración de subdominios, puertos, tecnologías |
| `src/cai/prompts/system_bb_web_analyzer_agent.md` | Análisis de arquitectura web, APIs, auth flows |
| `src/cai/prompts/system_bb_vulnhunter_agent.md` | Búsqueda de OWASP Top 10: XSS, SQLi, IDOR, SSRF |
| `src/cai/prompts/system_bb_exploit_agent.md` | PoC controlados, documentación de impacto |
| `src/cai/prompts/system_bb_report_agent.md` | Formato para HackerOne/Bugcrowd, criterios CVSS |

### Patrones de orquestación (4 ficheros)

Los patrones definen cómo se conectan los agentes entre sí (quién puede delegar a quién) y qué modelo LLM usa cada uno.

| Fichero | Función |
|---------|---------|
| `src/cai/agents/patterns/redteam_orchestrated.py` | **Patrón Red Team** — Clona los 6 agentes, asigna modelos por tier (Big/Medium/Small), crea los handoffs hub-and-spoke, verifica que los modelos estén disponibles en Ollama al importar. Configurable via env vars: `CAI_ORCH_MODEL`, `CAI_RECON_MODEL`, etc. |
| `src/cai/agents/patterns/bb_orchestrated.py` | **Patrón Bug Bounty** — Análogo al Red Team pero con los 6 agentes de BB |
| `src/cai/agents/patterns/multi_model_swarm.py` | **Soporte multi-modelo** — Patrón base que permite que cada agente en un swarm use un modelo diferente mediante el flag `_lock_model` |
| `src/cai/agents/patterns/multi_model_redteam.py` | Variante experimental del patrón multi-modelo para Red Team |

### Sistema de Tool Profiles (15 ficheros)

**Por qué**: Cuando el LLM ejecuta herramientas de seguridad (nmap, sqlmap, hydra…), a menudo omite flags esenciales o genera outputs demasiado largos que desperdician contexto. El sistema de Tool Profiles añade una capa modular que puede:
- **Pre-procesar** comandos: añadir flags que evitan que la herramienta falle (ej: sqlmap sin `--forms` cuando no hay parámetros GET → error CRITICAL).
- **Post-procesar** resultados: extraer un resumen estructurado del output bruto (ej: de 200 líneas de nmap, extraer solo los puertos abiertos).

Cada perfil es un fichero Python independiente que exporta una variable `PROFILE` de tipo `ToolProfile`. Los perfiles se auto-descubren al importar el paquete (via `pkgutil`), sin necesidad de registrarlos manualmente.

**Fichero registry** (`src/cai/tools/reconnaissance/tool_profiles/__init__.py`):
- Define la clase `ToolProfile` (dataclass con `name`, `pattern` regex, `smart_defaults`, `post_process`, `priority`)
- `_discover_profiles()`: escanea el directorio con `pkgutil.iter_modules`, importa cada módulo y recoge los que tengan `PROFILE`
- `apply_profiles_pre(command)`: busca el primer perfil que matchea la regex y aplica pre-procesado
- `apply_profiles_post(command, result)`: ídem para post-procesado
- Configurable via `CAI_TOOL_SMART_DEFAULTS` (default: `true`)

**Perfiles individuales** (14 ficheros en `src/cai/tools/reconnaissance/tool_profiles/`):

| Fichero | Herramienta | Pre-procesado (smart defaults) | Post-procesado |
|---------|-------------|-------------------------------|----------------|
| `nmap.py` | nmap (escaneo de puertos) | — | Extrae resumen `--- OPEN PORTS SUMMARY ---` con puertos abiertos y servicios |
| `sqlmap.py` | sqlmap (inyección SQL) | **Activado**: añade `--forms --crawl=2` cuando la URL no tiene `?` (parámetros GET). Sin esto sqlmap falla con `[CRITICAL] no parameter(s) found` | — |
| `hydra.py` | hydra (fuerza bruta) | — | Extrae credenciales encontradas: `login: X password: Y` |
| `john.py` | John the Ripper (cracking) | **Activado**: añade `--wordlist=/usr/share/wordlists/rockyou.txt` cuando no se especifica modo (sin wordlist john usa reglas incrementales, demasiado lento) | Extrae hashes crackeados |
| `hashcat.py` | hashcat (cracking GPU) | — | Extrae hashes crackeados |
| `gobuster.py` | gobuster (directorios) | — | Extrae paths descubiertos con status codes |
| `ffuf.py` | ffuf (fuzzing) | — | Extrae endpoints descubiertos |
| `dirb.py` | dirb (directorios) | — | Extrae URLs encontradas |
| `nikto.py` | nikto (web scanner) | — | Extrae hallazgos de seguridad |
| `wfuzz.py` | wfuzz (fuzzing) | — | Extrae hits (respuestas no filtradas) |
| `whatweb.py` | whatweb (fingerprinting) | — | Extrae tecnologías detectadas |
| `wpscan.py` | wpscan (WordPress) | — | Extrae vulnerabilidades y hallazgos |
| `searchsploit.py` | searchsploit (exploits) | — | Extrae exploits encontrados |
| `enum4linux.py` | enum4linux (SMB/Linux) | — | Extrae usuarios, shares y grupos |

### Servidor MCP de Burp Suite (2 ficheros)

**Por qué**: Burp Suite Professional es la herramienta estándar de la industria para testing web. El servidor MCP permite que los agentes de CAI usen Burp como herramienta adicional, lanzando escaneos y obteniendo vulnerabilidades descubiertas de forma automática. MCP (Model Context Protocol) es un protocolo estándar que permite a los LLMs interactuar con herramientas externas.

| Fichero | Función |
|---------|---------|
| `examples/mcp/burpsuite_example/server.py` | **Servidor MCP** que expone la API REST de Burp Suite como herramientas MCP. Implementa 8 herramientas: `burp_scan` (lanzar escaneo), `burp_scan_status` (estado), `burp_spider` (crawling), `burp_sitemap` (mapa del sitio), `burp_get_issues` (vulnerabilidades), `burp_get_issue_details` (detalle con request/response), `burp_send_to_repeater` (reenviar petición), `burp_proxy_history` (historial de proxy). Configurable via `BURP_API_URL` y `BURP_API_KEY` |
| `examples/mcp/burpsuite_example/README.md` | Guía de instalación y uso: cómo arrancar Burp con la API REST, instalar dependencias (`mcp[server] requests`), arrancar el servidor, y cargarlo en CAI (`/mcp load http://localhost:8000/sse burp`) |

### Infraestructura de testing (13 ficheros)

El CAI original no tenía tests. Se creó una suite completa con pytest.

| Fichero | Tests | Qué verifica |
|---------|-------|--------------|
| `tests/core/test_text_tool_call_extraction.py` | 39 tests | Detección de tool calls escritas como texto: estilo Python `tool(arg="val")`, JSON `{"name":"tool"}`, handoffs fuzzy `{"name":"delegate","agent":"Recon"}`, y **code blocks** `` ```bash\nnmap...\n``` `` |
| `tests/agents/test_redteam_orchestrated.py` | 9 tests | Handoffs del patrón Red Team: Orch→Recon→back, cadena completa, max_turns, `_lock_model` |
| `tests/agents/test_redteam_tools_integration.py` | 17 tests | Tool profiles: que nmap/sqlmap/hydra/etc ejecutan con los perfiles correctos |
| `tests/tools/test_tool_profiles.py` | 45 tests | Auto-discovery de 14 perfiles, pattern matching, smart defaults, post-processing |
| `tests/core/test_responses.py` | — | Tests de respuestas del modelo |
| `tests/conftest.py` | — | Configuración de pytest, fixtures compartidas |
| `tests/fake_model.py` | — | FakeModel para simular respuestas del LLM sin llamar a Ollama |
| `tests/helpers.py` | — | Funciones auxiliares para tests |
| `tests/testing_processor.py` | — | Procesador de tests |
| `tests/*/__init__.py` (×4) | — | Paquetes Python |

### Comando REPL `/state` (1 fichero)

**Por qué**: `write_key_findings` abre `state.txt` en modo append. Tras múltiples handoffs y sesiones, el fichero acumula secciones duplicadas (credenciales repetidas, hallazgos idénticos), contaminando el contexto cuando se lee. No existía forma de gestionarlo desde el REPL.

| Fichero | Función |
|---------|---------|
| `src/cai/repl/commands/state.py` | **Comando `/state`** (alias `/findings`). Subcomandos: `show` (muestra contenido), `clear` (borra el fichero), `write <contenido>` (sobreescribe, no append), `path` (muestra ruta absoluta). Sin argumentos, ejecuta `show`. Sigue el patrón de `flush.py` |

### Tests adicionales (4 ficheros)

| Fichero | Tests | Qué verifica |
|---------|-------|--------------|
| `tests/core/test_isolated_context.py` | 30 tests | Sistema completo de contexto aislado: inyección de briefing en handoffs, filtrado por offset, no duplicación en round-trips A→B→A, crecimiento lineal del historial |
| `tests/core/test_can_finish.py` | 6 tests | Campo `can_finish`: default True, configurable a False, preservado en clone, specialists False en redteam, orchestrator/report True |
| `tests/repl/test_state_command.py` | 10 tests | Comando `/state`: show sin fichero, show con contenido, clear borra, clear sin fichero no falla, write sobreescribe, dispatch de subcomandos |
| `tests/core/test_text_tool_call_extraction.py` | 4 tests adicionales | Detección case-insensitive: `Think(thought=...)`, `GENERIC_LINUX_COMMAND(...)`, `Generic_Linux_Command(...)`, `Transfer_To_Recon_Agent()` |

---

## Ficheros modificados

### SDK Core

#### `src/cai/sdk/agents/_run_impl.py` — Detección de tool calls en texto + control de finalización

**Por qué**: Los modelos locales pequeños (qwen3:8b, llama3.3) a veces escriben las llamadas a herramientas como texto plano en vez de usar el mecanismo nativo de function calling. El CAI original solo detectaba JSON simple. Se amplió para detectar 4 patrones diferentes.

**Cambios (líneas 4-270 aprox.)**:

| Líneas originales | Cambio | Motivo |
|-------------------|--------|--------|
| L7 | Añadido `import re` | Necesario para las regex de detección |
| L82-90 | **Nuevas constantes**: `_LLM_SPECIAL_TOKENS`, `_PYTHON_KWARGS_RE`, `_CODE_BLOCK_RE` | `_LLM_SPECIAL_TOKENS = ["<\|python_tag\|>", "<\|im_start\|>", "<\|im_end\|>"]` — tokens especiales que los modelos Ollama insertan en su output y que hay que limpiar antes de parsear. `_CODE_BLOCK_RE` — regex para detectar bloques `` ```bash `` |
| L92-105 | **Nueva función** `_build_name_maps()` | Construye un diccionario unificado nombre→tipo para funciones y handoffs, y un mapa inverso agent_name→tool_name para handoffs |
| L108-121 | **Nueva función** `_extract_balanced_parens()` | Extrae el contenido entre paréntesis balanceados — necesario para parsear `tool(arg="valor con (parens)")` |
| L124-135 | **Nueva función** `_parse_args()` | Parsea argumentos en formato JSON (`{"key":"val"}`) o Python kwargs (`key="val"`) |
| L138-157 | **Refactorizada** `_iter_json_candidates()` | Antes estaba inline en `_try_extract_text_tool_call`. Ahora es un generador reutilizable que yield bloques `{…}` balanceados |
| L160-175 | **Nueva función** `_try_python_style()` | Detecta llamadas estilo Python: `transfer_to_recon_agent()`, `generic_linux_command(command="nmap 10.0.0.1")`, incluyendo con tokens especiales `<\|python_tag\|>tool()` |
| L178-213 | **Nueva función** `_try_json_object()` | Detecta JSON: `{"name":"tool","parameters":{...}}`. Incluye **fuzzy matching**: si el modelo inventa un nombre como `"delegate"` con campo `"agent":"Recon Agent"`, lo resuelve al handoff correcto |
| L216-234 | **Nueva función** `_try_code_block()` | Detecta comandos raw en bloques markdown `` ```bash\ncurl http://...\n``` `` y los envuelve como `generic_linux_command(command="curl http://...")`. Solo actúa si `generic_linux_command` está en las herramientas del agente |
| L237-270 | **Reescrita** `_try_extract_text_tool_call()` | Antes: solo detectaba JSON, devolvía `(name, params)`. Ahora: cadena de 3 intentos (Python → JSON → Code Block), devuelve `(name, params, kind)` donde kind="function"\|"handoff". Acepta `handoff_map` además de `function_map` |
| L624-670 | **Ampliada** la sección que procesa tool calls detectadas en texto | Antes: solo creaba `ToolCallItem` + `ToolRunFunction`. Ahora: si `kind=="handoff"`, crea `HandoffCallItem` + `ToolRunHandoff` en su lugar. Esto permite que handoffs escritos como texto (no via function calling) se ejecuten correctamente |

**Cambios posteriores (commits `17517c7`, `86d4d26`)**:

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L169-170 | **Fix case-insensitive** en `_try_python_style()` | Añadido `clean_lower = clean.lower()` y búsqueda sobre `clean_lower` en vez de `clean`. Los modelos a veces escriben `Think(thought=...)` o `Generic_Linux_Command(...)` con mayúsculas — antes no se detectaban |
| L603-632 | **Nuevo método** `_maybe_force_handoff()` | Si un agente con `can_finish=False` produce una respuesta sin tool calls (que normalmente terminaría la sesión), fuerza un handoff al primer agente de su lista de handoffs. Devuelve `SingleStepResult(next_step=NextStepHandoff(...))` o `None` si no aplica |
| L558-562, L577-581 | **Guardas** antes de `execute_final_output` | Insertadas en los dos paths de finalización (structured output y plain text). Llaman a `_maybe_force_handoff()` y retornan el resultado forzado si aplica, evitando que el agente termine la sesión |

#### `src/cai/sdk/agents/models/openai_chatcompletions.py` — Modelo principal

**Por qué**: Este fichero contiene toda la lógica de comunicación con el LLM. Se modificó para: (a) soportar correctamente Ollama, (b) evitar duplicación de mensajes en swarm mode, (c) manejar errores de modelos no encontrados, (d) hacer que auto-compact funcione con modelos locales.

**Cambios**:

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L121-137 | **Nuevas constantes**: `_TOOL_CALL_AGENT_REGISTRY`, `_ollama_context_cache`, `_CLOUD_DEFAULT_MAX_TOKENS`, `_OLLAMA_FALLBACK_MAX_TOKENS` | `_TOOL_CALL_AGENT_REGISTRY`: diccionario global que mapea tool_call_id → nombre del agente que lo originó. Necesario porque tras un handoff, el agente receptor muestra las respuestas de herramientas del agente anterior con nombre incorrecto. `_ollama_context_cache`: cache para no consultar `/api/show` de Ollama en cada turno. `_CLOUD_DEFAULT_MAX_TOKENS = 200_000`: fallback para APIs cloud. `_OLLAMA_FALLBACK_MAX_TOKENS`: configurable via `CAI_OLLAMA_FALLBACK_CTX`, default 32768 |
| L396-401 | **Corregida** detección de Ollama | Antes: `os.getenv("OLLAMA") is not None and .lower() != "false"`. Ahora: también detecta Ollama si `OLLAMA_API_BASE` está definido (que es el caso habitual). Sin esto, muchas optimizaciones para Ollama no se activaban |
| L1050-1052 | **Añadido** registro en `_TOOL_CALL_AGENT_REGISTRY` | Al crear un tool call, se registra qué agente lo originó para poder mostrar el nombre correcto al imprimir la respuesta |
| L1098-1112 | **Ampliado** logging de herramientas | Se incluyen los handoffs además de las funciones en los datos de entrenamiento, útil para debugging |
| L2570-2602 | **Corregida** duplicación de mensajes en swarm mode | **Problema**: En modo swarm (multi-agente), `message_history` ya contiene toda la conversación. Pero el código original también convertía `generated_items` via `items_to_messages(input)`, que contenía lo mismo → cada mensaje se enviaba 2 veces al LLM, desperdiciando tokens y confundiendo al modelo. **Solución**: Si `message_history` tiene contenido, usarlo exclusivamente. Si no (primer turno), convertir `input` |
| L2602-2605 | **Añadida** llamada a `_sanitize_tool_call_pairs()` | Limpia tool_calls huérfanos antes de enviar al LLM (ver más abajo) |
| L2895 | **Incrementado** `max_retries` de 3 a 5 | Los modelos Ollama en servidor compartido fallan más frecuentemente por carga |
| L3003-3058 | **Nuevos handlers de error**: `TimeoutError`, `ServiceUnavailableError` (503), `NotFoundError` (404), model-not-found via 400 | **Problema**: Cuando un modelo no existía en Ollama o el servidor estaba ocupado, el error era críptico o la ejecución se colgaba. **Solución**: Mensajes claros con el comando `ollama pull` para instalarlo, reintentos con backoff para 503, y timeout configurable via `CAI_MODEL_TIMEOUT` |
| L3540-3555 | **Añadido** timeout configurable a `litellm.acompletion()` | Leído de `CAI_MODEL_TIMEOUT` (default 300s). Sin esto, peticiones a modelos grandes (72B) podían colgarse indefinidamente |
| L3558-3612 | **Nuevo método** `_sanitize_tool_call_pairs()` | **Problema**: Tras un handoff en modo swarm, el `message_history` compartido puede contener tool_calls del agente anterior sin sus respuestas tool correspondientes (porque se añadieron a `generated_items`, no a `message_history`). Ollama rechaza estas secuencias inválidas silenciosamente, causando que el agente se cuelgue. **Solución**: Escanea la conversación, encuentra tool_calls sin respuesta, y añade respuestas placeholder `"[handoff — tool processed by previous agent]"` |
| L3614-3661 | **Reescrito** `_get_model_max_tokens()` | **Problema**: El original buscaba en `pricing.json` (que solo tiene modelos cloud) y devolvía 200K por defecto → para modelos Ollama (contexto real ~32K), el threshold de auto-compact (80% = 160K) nunca se alcanzaba → auto-compact nunca se disparaba → el contexto crecía hasta que el modelo degeneraba. **Solución**: Orden de resolución: 1) pricing.json, 2) cache de Ollama, 3) query a `/api/show` de Ollama (cacheada), 4) fallback conservador (32K si Ollama, 200K si cloud) |
| L4272-4277 | **Añadido** `agent_name` desde `_TOOL_CALL_AGENT_REGISTRY` en tool metadata | Para mostrar el nombre correcto del agente al imprimir resultados de herramientas tras un handoff |
| L4371-4380 | **Corregido** `agent_name` en respuestas de herramientas | Usa el registro global en lugar de `model_instance.agent_name` (que tras un handoff es el agente receptor, no el originador) |

**Cambio posterior (commit `cf8db7e`)**:

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L3060-3080 | **Retry en respuesta vacía** de modelos thinking (qwen3) | **Problema**: qwen3 a veces devuelve una respuesta vacía (content="" sin tool_calls) porque gasta todos los tokens en `<think>...</think>` interno. **Solución**: Si la respuesta es vacía y queda budget de reintentos, se reintenta la petición con un delay. Máximo 3 reintentos con backoff |

#### `src/cai/sdk/agents/run.py` — Runner principal + contexto aislado

**Por qué**: Este fichero contiene el bucle principal de ejecución de agentes (`Runner.run`). Se extendió con el sistema de contexto aislado per-agent para que cada agente en un swarm mantenga su propio historial independiente, recibiendo solo briefings compactos en los handoffs.

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L14-20 | **Nuevas constantes** `_HANDOFF_CONTEXT_MESSAGES`, `_HANDOFF_MSG_TRUNCATE`, `_TOOL_OUTPUT_TRUNCATE=800`, `_MAX_COMMANDS_IN_BRIEFING=15`, `_MAX_FINDINGS_IN_BRIEFING=1500`, `_MAX_BRIEFINGS_PER_AGENT=3`, `_FINDINGS_TOOLS` (frozenset) | Configuración del sistema de briefing estructurado |
| L148-157 | **Nueva función** `_read_state_for_briefing()` | Lee `state.txt` (vía `_state_file_path()`) y lo trunca a `_MAX_FINDINGS_IN_BRIEFING` caracteres para incluirlo en la sección de findings del briefing |
| L159-281 | **Función reescrita** `_inject_handoff_context(from_agent, to_agent, current_items_len)` | Reescrita completamente: en vez de copiar N mensajes crudos, parsea el historial del agente origen en secciones semánticas (`## Commands Executed`, `## Key Tool Outputs`, `## Agent Conclusion`, `## Current Findings`). Excluye tool calls de findings (`write_key_findings`, `read_key_findings`, `thought`, `think`). Reemplaza briefings anteriores del mismo agente origen. Limita a `_MAX_BRIEFINGS_PER_AGENT` briefings de fuentes distintas. Siempre rompe referencias compartidas de historial |
| L294-300 | **Añadido** logging de handoffs | `logger.info("Handoff: AgentA → AgentB (model: qwen2.5:32b)")` |
| L356-393 | **Lógica de handoff con aislamiento** | Al detectar un handoff, comprueba si alguno de los agentes tiene `isolated_context=True`. Si sí: llama a `_inject_handoff_context()` (briefing compacto). Si no: comparte `message_history` por referencia (comportamiento original). Registra el agente en `AGENT_MANAGER` |
| L836-848 | **Filtrado por offset en streaming** | Cuando un agente con `isolated_context` ejecuta un turno, en vez de pasar todos los `generated_items`, filtra por `offset` y `agent.name`. Solo incluye items creados después del último handoff que pertenecen a este agente. Actualiza el offset tras cada turno |
| L940-948 | **Mismo filtrado** en la ruta no-streaming | Duplicado necesario porque hay dos paths de ejecución (`_run_single_turn_streamed` y `_run_single_turn`) |
| L186 | **Fix**: filtro `WARNING:` en extracción de objective | Los nudge warnings de repetición se inyectan como `role: "user"`. Sin el filtro, `_inject_handoff_context` los extraía como `## Objective` en vez del objetivo real del usuario |
| L192-224 | **Nuevo**: extracción de `user_instructions` post-briefing | Extrae mensajes de usuario posteriores al último briefing recibido (`[Handoff from ...]`) y los incluye como `## User Instructions (HIGH PRIORITY)` en el briefing. Filtra warnings, auto-continue y briefings. Previene duplicación en handoffs circulares (A→B→A→C) al solo extraer instrucciones posteriores al último briefing recibido |
| L291 | **Nueva sección** `## User Instructions (HIGH PRIORITY)` en briefing | Insertada después de `## Objective`, antes de `## Commands Executed` |
| L1120-1148 | **Fix crítico**: preservar user input del CLI en `isolated_context` | **Bug**: con `isolated_context=True`, `_run_single_turn` descartaba `original_input` y lo reemplazaba con items de `generated_items`. La instrucción del usuario post-Ctrl+C (que venía en `original_input` desde el CLI) se perdía al 100%. **Fix**: antes de descartar `original_input`, extrae el último mensaje de usuario que no sea un mensaje del sistema y lo añade a `agent.model.message_history` + lo registra en el JSONL log |

#### `src/cai/sdk/agents/agent.py` — Definición base del agente

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L162-166 | **Nuevo campo** `_lock_model: bool = False` | Cuando es `True`, el factory y el CLI no sobreescriben el modelo del agente. Necesario para que los patrones multi-modelo funcionen — sin esto, el CLI aplicaba `CAI_MODEL` a todos los agentes, anulando la asignación por tiers (Big/Medium/Small) |
| L168-172 | **Nuevo campo** `isolated_context: bool = False` | Cuando es `True`, el agente mantiene su propio `message_history` independiente. En los handoffs recibe un briefing compacto (últimos N mensajes) en vez de compartir todo el historial. Evita el crecimiento exponencial del contexto en swarms multi-agente |
| L174-178 | **Nuevo campo** `can_finish: bool = True` | Cuando es `False`, el agente no puede producir un output final que termine la sesión. Si genera una respuesta sin tool calls, el framework fuerza un handoff al primer agente de su lista de handoffs. Usado para que solo Orchestrator y Report puedan terminar la sesión |

### Agentes y Factory

#### `src/cai/agents/factory.py` — Fábrica de agentes

**Por qué**: El factory clona agentes y les asigna el modelo de `CAI_MODEL`. Esto rompía los patrones multi-modelo porque sobreescribía las asignaciones por tier.

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L66-69 | **Nuevo check** `_lock_model` | Si el agente original tiene `_lock_model=True` y no hay override explícito del usuario, se conserva su modelo original en lugar de aplicar `CAI_MODEL` |
| L73-75 | **Propagación** de `_lock_model` al clon | El atributo `_lock_model` se copia al agente clonado para que toda la cadena de handoffs lo respete |

#### `src/cai/agents/__init__.py` — Registro de agentes

**Por qué**: El sistema de registro creaba "pseudo-agentes" (`PatternAgent`) para cada patrón. Estos pseudo-agentes no tenían handoffs ni modelo, y sobreescribían los agentes reales del patrón orquestado.

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L128-134 | **Nuevo guard** antes de crear pseudo-agentes | Si ya existe un Agent real registrado con ese nombre (por ejemplo, el Orchestrator del patrón Red Team), no lo sobreescribe con un PatternAgent vacío |
| L262-264 | **Propagación** de `_lock_model` en la otra ruta de clonación | Consistencia con factory.py |

#### `src/cai/agents/patterns/redteam_orchestrated.py` — Patrón Red Team

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L147-150 | **`can_finish=False`** en 4 especialistas | Tras configurar los handoffs, se establece `can_finish=False` en Recon, Strategy, Exploitation y PrivEsc. Solo Orchestrator y Report mantienen `can_finish=True`. Esto evita que un especialista termine la sesión accidentalmente al generar texto sin tool calls |

#### `src/cai/agents/web_pentester.py` — Agente web pentester

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L17, L33 | **Eliminada** importación y uso de `js_surface_mapper` | La herramienta `js_surface_mapper.py` fue eliminada del proyecto (ver [Fichero eliminado](#fichero-eliminado)) |

### REPL

#### `src/cai/repl/commands/__init__.py` — Registro de comandos

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L37 | **Añadido** import de `state` | Registra el nuevo comando `/state` en el sistema de comandos del REPL |

### CLI

#### `src/cai/cli.py` — Interfaz de línea de comandos

**Por qué**: El CLI necesitaba respetar `_lock_model` y actualizar el agente activo tras handoffs.

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L371-377 | **Modificada** `update_agent_models_recursively()` | Si el agente tiene `_lock_model=True`, se salta la actualización de modelo. Sin esto, al cambiar de modelo en el CLI, se rompían las asignaciones multi-modelo |
| L563 | **Añadido** check `_lock_model` | El bucle principal no actualiza modelos de agentes bloqueados |
| L658-668 | **Condicionado** apply model tras handoff | Solo aplica el modelo actual si el agente no tiene `_lock_model` |
| L1595-1602 | **Nuevo**: actualización de agente activo tras streaming | **Problema**: Tras un handoff en modo streaming, el CLI seguía mostrando el nombre del agente anterior. **Solución**: Se lee `stream_result.last_agent` y se actualiza `AGENT_MANAGER` |
| L1637-1644 | **Mismo fix** para la ruta de nuevo event loop | Duplicado necesario porque hay dos rutas de ejecución de streaming |
| L1736-1742 | **Mismo fix** para la ruta de `Runner.run()` (no streaming) | Actualiza el agente activo tras handoff en modo no-streaming |
| L1919-1921 | **Condicionado** model override al inicio | No aplica `CAI_MODEL` si el agente tiene `_lock_model` |
| L1824-1842 | **Nuevo**: HITL prompt en `continue_mode` tras Ctrl+C | En modo continuo, tras Ctrl+C se muestra un prompt para que el usuario pueda inyectar instrucciones. Si escribe algo, se inyecta como mensaje `user` en el historial del agente activo y se pone como `_auto_continue_input`. Si Enter vacío, resume auto-continue. Si doble Ctrl+C, sale al prompt normal |

### Herramientas

#### `src/cai/tools/reconnaissance/generic_linux_command.py` — Comando genérico

**Por qué**: Esta es la herramienta principal que los agentes usan para ejecutar cualquier comando de terminal. Se modificó para integrar el sistema de Tool Profiles, que pre-procesa los comandos antes de ejecutarlos y post-procesa los resultados.

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L393-398 (añadidas) | **Integración pre-procesado**: `from cai.tools.reconnaissance.tool_profiles import apply_profiles_pre` + `command = apply_profiles_pre(command)` | Justo antes de ejecutar el comando, se busca si existe un Tool Profile que matchee (ej: sqlmap, nmap) y se aplican los smart defaults. Esto se hace **después** de las validaciones de seguridad pero **antes** de la ejecución |
| L397-399 | **Obtención de timeouts por perfil**: `get_idle_timeout()` y `get_max_execution_time()` | Consulta el Tool Profile para obtener el `idle_timeout` (default 10s) y `max_execution_time` (default 0=sin límite) específicos de la herramienta. Pasa ambos valores a las 3 llamadas de ejecución (`run_command` session, `run_command` interactive, `run_command_async`) |
| L402-406 (añadidas) | **Fix timeout override**: `if max_execution_time > 0 and max_execution_time > timeout: timeout = max_execution_time` | **Bug**: en la ruta non-streaming (`CAI_STREAM=false`), el `timeout=100` por defecto del parámetro de función se evaluaba ANTES que `max_execution_time=300` del perfil, matando sqlmap a los 100s en vez de los 300s. Este override propaga el valor del perfil al parámetro `timeout` |
| L456-460 (añadidas) | **Integración post-procesado**: `from cai.tools.reconnaissance.tool_profiles import apply_profiles_post` + `result = apply_profiles_post(command, result)` | Tras la ejecución, se busca el perfil correspondiente y se procesa el resultado (ej: de 200 líneas de output de nmap, se extrae un resumen de puertos abiertos). Esto se hace **antes** del sanitizado de guardrails |

#### `src/cai/tools/common.py` — Funciones de ejecución de comandos

**Por qué**: Las funciones de ejecución (`_run_local_async`, `_run_docker_async`, `run_command_async`, `run_command`) tenían el idle timeout hardcodeado a 10 segundos y no tenían límite de ejecución total. sqlmap con time-based blind SQLi se mataba a los 10s (idle) o ejecutaba indefinidamente (sin cap total).

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L628, L955, L1450, L1567 | **Nuevo parámetro** `idle_timeout=10` en 4 funciones | Permite configurar por herramienta el tiempo máximo sin stdout antes de matar el proceso. Reemplaza los 3 hardcoded `> 10` por `> idle_timeout` |
| L628, L955, L1450, L1567 | **Nuevo parámetro** `max_execution_time=0` en 4 funciones | Límite absoluto de ejecución en segundos. 0=sin límite (default). El proceso se mata tras este tiempo independientemente de si produce output |
| L706-715 | **Check `max_execution_time`** en streaming loop de `_run_local_async` | Al inicio del `while True`, comprueba si se superó el tiempo máximo. Si sí: `terminate()` → `kill()` → `break` con mensaje `[Terminated: max execution time Xs reached]` |
| L795-805 | **Check `max_execution_time`** en non-streaming loop de `_run_local_async` | Mismo check en la ruta sin streaming |
| L1042-1052 | **Check `max_execution_time`** en streaming loop de `_run_docker_async` | Mismo check para ejecución en Docker |
| L721, L801, L1041 | **Mensajes de terminación** con f-string | `f"\n[Terminated: idle {idle_timeout}s]"` en vez de hardcoded `10` |
| L628, L955 | **Añadido** `start_new_session=True` en `create_subprocess_shell` | Crea el proceso en un nuevo grupo de sesión (POSIX). Permite matar todo el árbol de procesos con `os.killpg()` en vez de solo el proceso padre. Necesario porque herramientas como sqlmap lanzan procesos hijos que sobreviven a `process.kill()` |
| L700-710 | **Nueva función** `_kill_process_tree(process)` | Helper que mata todo el grupo de procesos con `os.killpg(os.getpgid(pid), SIGKILL)`. Fallback a `process.kill()` si falla. Reemplaza todos los `process.kill()` y `process.terminate()` en las rutas de timeout |
| L706-715, L795-805 | **Reemplazado** `process.terminate()`/`process.kill()` por `_kill_process_tree()` | En streaming y non-streaming de `_run_local_async`. Detectado en ejecución real donde sqlmap hijos se quedaron ejecutando 30+ min tras el timeout del proceso padre |

#### `src/cai/tools/reconnaissance/tool_profiles/__init__.py` — Registry de perfiles

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L44-49 | **Nuevo campo** `idle_timeout: int = 10` | Timeout de detección de inactividad. El proceso se mata si no produce stdout durante este tiempo. Default 10s. Configurable por perfil |
| L50-52 | **Nuevo campo** `max_execution_time: int = 0` | Tiempo máximo total de ejecución. 0=sin límite. El proceso se mata después de este tiempo sin importar si produce output |
| L137-142 | **Nueva función** `get_idle_timeout(command)` | Devuelve el `idle_timeout` del primer perfil que matchea, o 10 |
| L145-150 | **Nueva función** `get_max_execution_time(command)` | Devuelve el `max_execution_time` del primer perfil que matchea, o 0 |

#### `src/cai/tools/reconnaissance/tool_profiles/sqlmap.py` — Perfil sqlmap

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L25 | **`idle_timeout=120`** | sqlmap con time-based blind SQLi usa `SLEEP(5)` por carácter extraído, produciendo silencio >10s entre outputs. 120s da margen suficiente |
| L26 | **`max_execution_time=300`** | Cap de 5 minutos por invocación. Suficiente para extraer tablas/columnas. Si necesita más, el agente puede reinvocar con `--resume` |

#### `src/cai/tools/reconnaissance/filesystem.py` — Herramienta find

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L8-13 (eliminadas) | **Eliminada** constante `DANGEROUS_FIND_FLAGS` | Lista de flags de `find` considerados peligrosos (`-exec`, `-delete`, `-print0`, etc.) |
| L72-76 (eliminadas) | **Eliminada** validación de flags peligrosos | El bloqueo impedía el uso legítimo de `find -exec` en pentesting. En un contexto de red team/CTF, estas restricciones son contraproducentes |

### Prompts existentes (modificados)

#### `src/cai/prompts/system_bug_bounter.md`

| Líneas | Cambio |
|--------|--------|
| L52-75 (añadidas) | **Sección Burp Suite MCP**: lista de herramientas disponibles si Burp está cargado (`burp_spider`, `burp_scan`, `burp_get_issues`, etc.). **Ejemplos de tool calls**: `generic_linux_command(command="nmap...")`, `execute_code(code="...")`, `shodan_search(query="...")` — para que modelos pequeños vean el formato correcto de function calling |

#### `src/cai/prompts/system_triage_agent.md`

| Líneas | Cambio |
|--------|--------|
| L76-88 (añadidas) | **Ejemplos de tool calls**: curl a NVD API, searchsploit, PoC con requests, nmap con scripts vuln |

#### `src/cai/prompts/system_web_bounty_agent.md`

| Líneas | Cambio |
|--------|--------|
| L67-80 (añadidas) | **Ejemplos de tool calls**: curl con Authorization, ffuf, gau, waybackurls, IDOR test con Python |

#### `src/cai/prompts/system_recon_agent.md`

| Líneas | Cambio |
|--------|--------|
| Final | **Nueva sección** "CRITICAL: Findings Persistence" — instrucciones para que el agente use `write_key_findings` tras cada descubrimiento significativo y `read_key_findings` al inicio de cada turno para mantener estado entre handoffs |

#### `src/cai/prompts/system_exploitation_agent.md`

| Líneas | Cambio |
|--------|--------|
| Final | **Nueva sección** "CRITICAL: Findings Persistence" — mismas instrucciones de persistencia de hallazgos |

#### `src/cai/prompts/system_privesc_agent.md`

| Líneas | Cambio |
|--------|--------|
| Final | **Nueva sección** "CRITICAL: Findings Persistence" — mismas instrucciones de persistencia de hallazgos |

#### `src/cai/prompts/system_strategy_agent.md`

| Líneas | Cambio |
|--------|--------|
| Final | **Nueva sección** "CRITICAL: Findings Persistence" — instrucciones adaptadas al rol de estrategia: leer findings para evaluar progreso y escribir recomendaciones estratégicas |

#### `src/cai/prompts/system_orchestrator_agent.md`

| Líneas | Cambio |
|--------|--------|
| Final | **Nueva sección** "Findings Review" — instrucciones para que el orquestador lea `state.txt` al recibir un handoff para entender el estado actual del pentest |

#### `src/cai/prompts/system_web_pentester.md`

| Líneas | Cambio |
|--------|--------|
| L95-114 (eliminadas) | **Eliminada** sección "Business-Logic Abuse Backlog" — plantilla de 10-15 test cases para lógica de negocio que añadía complejidad innecesaria al prompt y consumía tokens sin aportar valor en la mayoría de escenarios |

---

## Fichero eliminado

| Fichero | Motivo |
|---------|--------|
| `src/cai/tools/web/js_surface_mapper.py` | Herramienta de extracción de endpoints desde JavaScript. Eliminada porque dependía de librerías externas no disponibles y su funcionalidad era redundante con otras herramientas de reconocimiento |

---

## Variables de entorno nuevas

| Variable | Default | Función |
|----------|---------|---------|
| `CAI_ORCH_MODEL` | `qwen2.5:72b` | Modelo para el Orchestrator (Red Team) |
| `CAI_RECON_MODEL` | `qwen3:14b` | Modelo para el agente de Reconocimiento |
| `CAI_STRATEGY_MODEL` | `qwen2.5:72b` | Modelo para el agente de Estrategia |
| `CAI_EXPLOIT_MODEL` | `qwen2.5:32b` | Modelo para el agente de Explotación |
| `CAI_PRIVESC_MODEL` | `qwen2.5:32b` | Modelo para el agente de Escalada de Privilegios |
| `CAI_REPORT_MODEL` | `qwen3:14b` | Modelo para el agente de Informe |
| `CAI_MODEL_TIMEOUT` | `300` | Timeout en segundos para peticiones al LLM |
| `CAI_AUTO_COMPACT` | `true` | Activa/desactiva la compactación automática del contexto |
| `CAI_AUTO_COMPACT_THRESHOLD` | `0.8` | Porcentaje de uso del contexto que dispara auto-compact (80%) |
| `CAI_OLLAMA_FALLBACK_CTX` | `32768` | Context length fallback cuando Ollama `/api/show` no responde |
| `CAI_TOOL_SMART_DEFAULTS` | `true` | Activa/desactiva los smart defaults de Tool Profiles (pre-procesado de comandos) |
| `BURP_API_URL` | `http://localhost:1337` | URL de la API REST de Burp Suite (para el servidor MCP) |
| `BURP_API_KEY` | `""` | API key opcional para autenticación con Burp Suite |
| `CAI_HANDOFF_CONTEXT_MESSAGES` | `10` | Número de mensajes del agente origen que se inyectan como briefing en un handoff con contexto aislado |
| `CAI_REPEAT_THRESHOLD` | `3` | Nº de ejecuciones consecutivas del mismo comando (normalizado) antes de inyectar un WARNING anti-repetición |
| `CAI_TOKEN_ESTIMATE_MULTIPLIER` | `1.4` (Ollama) / `1.0` (cloud) | Factor de calibración aplicado a la estimación de tiktoken para alinearla con los `prompt_tokens` reales de Ollama |
| `ZAP_API_URL` | `http://localhost:8080` | URL de la API REST de OWASP ZAP (para el servidor MCP) |
| `ZAP_API_KEY` | `""` | API key opcional para autenticación con ZAP |

---

## Fixes de bugs (alta y media severidad)

Tras una revisión exhaustiva del diff completo contra upstream, se identificaron y corrigieron 8 bugs.

### Alta severidad

#### `src/cai/tools/reconnaissance/tool_profiles/john.py` — Patrón de matching

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L48 | **Pattern** `r"\bjohn\b"` → `r"(?:^|&&|;|\|\|?|\bsudo\s+)\s*john\b"` | El patrón original matcheaba "john" como username o path (`cat /home/john/file`, `ssh john@target`), activando smart_defaults que corrompían el comando añadiendo `--wordlist=rockyou.txt` |

#### `src/cai/sdk/agents/_run_impl.py` — Detección de tool calls en texto

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L89 | **Regex extendida** `_PYTHON_KWARGS_RE` para capturar valores no-quoted | Solo capturaba `key="string"`, ignorando `port=8080` o `verbose=True`. Ahora usa grupo alternativo `(\S+?)(?:\s*[,)]|$)` |
| L134 | **Ajustado** `_parse_args` para usar `m.group(2) if m.group(2) is not None else m.group(3)` | Complementa la regex extendida: elige el grupo capturado correcto |
| L171-175 | **Word boundary check** en `_try_python_style` | `find(name + "(")` es substring match: `port_scan(...)` matcheaba `scan(`. Ahora verifica que el carácter anterior no sea alfanumérico ni `_` |

#### `src/cai/sdk/agents/models/openai_chatcompletions.py` — Retry nudge

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L770-784 | **Rollback del nudge** con bloque `finally` | El mensaje nudge `"Your previous response was empty..."` se añadía permanentemente a `message_history`, contaminando turnos futuros. Ahora se elimina tras el retry |
| L783 | **`except Exception: pass`** → `except Exception: logger.debug(...)` | Los errores de retry se tragaban silenciosamente |

#### `src/cai/sdk/agents/agent.py` — Campo del dataclass

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L180-182 | **Declarado** `_isolated_items_offset: int = 0` como campo | Era atributo dinámico: se perdía al usar `dataclasses.replace()` / `agent.clone()`, causando duplicación de mensajes en handoffs round-trip |

### Media severidad

#### `src/cai/tools/misc/reasoning.py` — Path de state.txt

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L11-18 | **Nueva función** `_state_file_path()` | Centraliza la resolución del path de state.txt. Usa `_get_workspace_dir()` de `common.py` para resolver correctamente la ruta (ej: `CAI_WORKSPACE=test` → `cwd/workspaces/test/state.txt`). **Bug corregido**: antes usaba `CAI_WORKSPACE` directamente como path, lo que con un nombre como "test" creaba `test/state.txt` relativo al CWD en vez de `workspaces/test/state.txt` |
| L57, L79 | **Reemplazado** `open("state.txt")` por `open(_state_file_path())` | En `write_key_findings` y `read_key_findings` |
| L71-76 | **Fix**: deduplicación en `write_key_findings` | Lee el contenido existente antes de appendear. Si `findings.strip()` ya existe en el fichero, retorna "skipped duplicate" sin escribir. Evita que state.txt acumule el mismo ATTACK PLAN 4+ veces en ciclos Strategy→Exploitation→Strategy |

#### `src/cai/repl/commands/state.py` — Path centralizado

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L8, L17-18 | **Import** `_state_file_path` de reasoning.py, `_state_path()` la delega | Antes tenía su propia resolución con `os.path.join(os.getcwd(), STATE_FILENAME)`. Ahora usa el helper centralizado para consistencia |

#### `src/cai/tools/reconnaissance/tool_profiles/sqlmap.py` — Heurística mejorada

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L10-27 | **Reescrita** `_sqlmap_smart_defaults` | La heurística `"?" not in command` buscaba `?` en todo el string. Ahora: (1) skip si detecta `--help`/`-r`/`-hh`; (2) parsea URL tras `-u`/`--url` con regex; (3) solo añade `--forms --crawl=2` si la URL no tiene query string |
| L19-20 | **Añadido** skip cuando `--data` presente | `--data` indica modo POST con puntos de inyección explícitos. Añadir `--forms --crawl=2` en ese caso hace que sqlmap ignore el `--data` y pierda tiempo crawleando. Detectado en ejecución real donde sqlmap se ejecutó 30+ min con flags contradictorios |

#### `src/cai/tools/reconnaissance/tool_profiles/__init__.py` — Detección de help output

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L55 | **Nuevo campo** `help_indicators: List[str]` en `ToolProfile` | Lista declarativa de strings que identifican una help page. Si TODOS están presentes en el output, se considera help |
| L83-87 | **Nuevo método** `is_help_output(result)` | Comprueba si el resultado contiene todos los indicadores de help del perfil |
| L89-101 | **Modificado** `apply_post()` | Antes de llamar a `post_process`, comprueba `is_help_output()`. Si detecta help, reemplaza el output completo con un mensaje de error claro que guía al modelo a verificar paths o cambiar de herramienta |

#### `src/cai/tools/reconnaissance/tool_profiles/ffuf.py` — Help indicators

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L32 | **Añadido** `help_indicators=["Fuzz Faster U Fool", "HTTP OPTIONS:"]` | Detecta cuando ffuf imprime su help (wordlist no encontrada) en vez de ejecutar el fuzzing |

#### `src/cai/tools/reconnaissance/tool_profiles/gobuster.py` — Help indicators

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L31 | **Añadido** `help_indicators=["Usage:", "gobuster [command]"]` | Detecta help page de gobuster |

#### `src/cai/tools/reconnaissance/tool_profiles/dirb.py` — Help indicators

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L31 | **Añadido** `help_indicators=["----- DIRB", "By The Dark Raver"]` | Detecta help page de dirb |

#### `src/cai/tools/reconnaissance/tool_profiles/wfuzz.py` — Help indicators

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L39 | **Añadido** `help_indicators=["Usage:", "wfuzz [options]"]` | Detecta help page de wfuzz |

#### `src/cai/sdk/agents/repetition_detector.py` — Detección de comandos repetidos (NUEVO)

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L1-100 | **Nuevo fichero** `RepetitionDetector` + `extract_last_commands()` | Detecta cuando un agente ejecuta el mismo comando (normalizado) N veces consecutivas. Normaliza reemplazando paths, URLs y strings con placeholders para comparar solo el patrón del comando. Threshold configurable via `CAI_REPEAT_THRESHOLD` (default: 3) |

#### `src/cai/sdk/agents/run.py` — Integración del detector de repeticiones

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L26 | **Import** `RepetitionDetector`, `extract_last_commands` | |
| L343 | **Init** `repetition_detector = RepetitionDetector()` | Inicializar antes del loop principal |
| L509 | **Reset** `repetition_detector.reset()` en handoff | Limpiar estado al cambiar de agente |
| L510-527 | **Check** en `NextStepRunAgain` | Tras cada turno, extrae comandos del último assistant message, los registra en el detector. Si alcanza threshold, inyecta WARNING en message_history forzando al agente a cambiar de estrategia |

#### `src/cai/sdk/agents/run.py` — Input vacío en contexto aislado

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L949-951 | **Input mínimo** cuando el filtro aislado queda vacío | Tras handoff, si un agente con `isolated_context=True` no tiene items propios, `input` quedaba como `[]`. Algunos modelos fallan sin mensaje user. Ahora inyecta `"Continue with your task..."` |

#### `src/cai/sdk/agents/run.py` — Objetivo del usuario en briefing de handoff

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L177-190 (añadidas) | **Extracción de `user_objective`**: primer user message que no sea briefing ni "Continue with your task" | **Bug**: el Orchestrator recibía "Pentest the ip 172.17.0.2" del usuario, pero al hacer handoff a Recon, el briefing solo contenía state.txt y tool outputs — la IP target nunca llegaba al especialista. Recon inventaba una IP (10.10.10.1), fallaba, y entraba en un ping-pong infinito con el Orchestrator |
| L255-256 (añadidas) | **Sección `## Objective`** como primera sección del briefing | El objetivo del usuario siempre aparece primero en el briefing, antes de Commands/Outputs/Conclusion/Findings. Se trunca a `_HANDOFF_MSG_TRUNCATE` caracteres. No se duplica: se filtra "Continue with your task" y briefings `[Handoff from ...]`, y el reemplazo de briefings del mismo source (L262-267) evita acumulación |

#### `src/cai/sdk/agents/_run_impl.py` — Warning can_finish

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L635-640 | **Warning** en `_maybe_force_handoff` | Si `can_finish=False` pero no hay handoffs definidos, la restricción se ignora silenciosamente. Ahora emite `logger.warning` para que el desarrollador detecte la configuración incoherente |

#### `src/cai/tools/reconnaissance/tool_profiles/__init__.py` — Helper `command_pattern`

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L24-33 | **Nueva función** `command_pattern(name)` | Genera un regex que matchea `name` solo como binario ejecutado (inicio de línea, tras `&&`, `;`, `\|`, `sudo`, `python`). Evita false positives cuando el nombre aparece en paths (e.g. `/usr/share/wordlists/dirb/`) |

#### `src/cai/tools/reconnaissance/tool_profiles/*.py` — Patrones actualizados (13 perfiles)

| Ficheros | Cambio | Motivo |
|----------|--------|--------|
| dirb, ffuf, gobuster, nmap, nikto, hydra, hashcat, wpscan, enum4linux, searchsploit, sqlmap, wfuzz, whatweb | **Reemplazado** `pattern=r"\b<name>\b"` por `pattern=command_pattern("<name>")` | Bug: `\bdirb\b` matcheaba "dirb" en paths como `/usr/share/wordlists/dirb/common.txt`, causando que `apply_profiles_post` aplicara el perfil de dirb en vez de ffuf. Rompía la detección de help pages |

#### `src/cai/sdk/agents/_run_impl.py` — Fix cross-block regex + validación texto-como-comando

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L90 | **Fix `_CODE_BLOCK_RE`**: `(?:bash\|sh\|shell)?` → `\w*` | **Bug de seguridad**: el regex anterior no consumía bloques con tags no-bash (` ```sql `, ` ```python `), causando cross-block matching. El ` ``` ` de cierre de un bloque sql se interpretaba como apertura de un bloque bare, capturando la prosa entre bloques como "comando". Con `\w*`, todos los bloques se consumen correctamente y se capturan comandos de cualquier tipo de bloque |
| L91-97 | **Nuevas constantes** `_PROSE_STARTERS_RE`, `_SHELL_OPERATORS_RE` | Regex compilados para detectar prosa vs comandos shell |
| L98-112 | **Nueva constante** `_SHELL_CONSTRUCT_RE` | Regex que detecta construcciones shell (`for VAR in`, `if [`, `while true`, `case ... in`, etc.) para evitar falsos negativos con keywords que también son prose starters |
| L116-149 | **Nueva función** `_looks_like_command(text)` | Heurística que: (1) acepta shell constructs primero, (2) rechaza prose starters, (3) rechaza frases con punto, (4) valida primer token. Evita que razonamiento del modelo se ejecute como comando |
| L299 | **Integrado** en `_try_code_block` | Añadido `and _looks_like_command(cmd)` al check antes de envolver como `generic_linux_command` |

#### `src/cai/util.py` — Fix loop infinito en `fix_message_list`

**Por qué**: `fix_message_list` sanitiza la lista de mensajes para cumplir con el formato de la API de OpenAI. Su segundo pass reordena tool messages desplazados junto a su assistant. Tenía un **bug crítico** que causaba un loop infinito, bloqueando CAI completamente (detectado con py-spy tras 43+ minutos de ejecución).

| Líneas | Cambio | Motivo |
|--------|--------|--------|
| L1243 (añadida) | **`relocated_tool_ids: set = set()`** | Set que rastrea qué `tool_call_id`s ya han sido reubicados |
| L1249-1254 (añadidas) | **Guard clause**: `if tool_id in relocated_tool_ids: i += 1; continue` | Si un tool message ya fue movido una vez, se salta en vez de reubicarlo de nuevo |
| L1293 (añadida) | **`relocated_tool_ids.add(tool_id)`** después de `pop()`+`insert()` | Registra cada tool message reubicado para que el guard lo detecte |

**Bug**: Cuando un assistant tiene múltiples tool_calls (ej: `[id_A, id_B]`) y sus tool responses están consecutivas pero no inmediatamente después del assistant, el segundo pass hacía `pop(i)` + `insert(assistant_idx+1)` + `continue` (sin incrementar `i`). Los dos tool responses se intercambiaban indefinidamente: tool_B se movía a posición `j+1`, lo que desplazaba tool_A a `j+2` (=`i`), que al procesarse se movía a `j+1` desplazando tool_B de vuelta a `i`, etc. El fix marca cada tool message como "ya reubicado" tras su primer movimiento, rompiendo el ciclo.

### Tests añadidos

| Fichero | Tests | Cobertura |
|---------|:-----:|-----------|
| `tests/tools/test_tool_profiles.py` | +28 | `TestJohnPatternFalsePositives` (10), `TestSqlmapSmartDefaultsImproved` (5), existente actualizado (1), `TestHelpOutputDetection` (7), `TestPatternMatchingFix` (5) |
| `tests/core/test_repetition_detector.py` | +12 | **Nuevo**: `TestRepetitionDetector` (8) — threshold, reset, normalización, env var; `TestExtractLastCommands` (4) — extracción de comandos de message_history |
| `tests/core/test_text_tool_call_extraction.py` | +26 | `TestSubstringFalsePositives` (3), `TestNumericArgsParsing` (3), prose rejection (4), command acceptance (4), comment handling (2), cross-block fix (3), all-block capture (2), shell constructs (5) |
| `tests/core/test_empty_response_retry.py` | +3 | **Nuevo**: `TestNudgeRollback` — verifica que el nudge no persiste |
| `tests/core/test_isolated_context.py` | +23 | `TestIsolatedItemsOffsetDataclass` (3) — offset sobrevive a clone; `TestStructuredBriefing` (16) — secciones del briefing, exclusión de findings tools, truncado, reemplazo de briefings, límite máximo, integración con state.txt, objective extraction (4 tests); `TestBriefingObjectiveFiltering` (4) — skips WARNING messages, propaga user instructions post-objective, skips auto-continue, no duplica en handoffs circulares |
| `tests/core/test_can_finish.py` | +1 | `TestCanFinishNoHandoffsWarning` — verifica warning en logs |
| `tests/core/test_fix_message_list.py` | +5 | **Nuevo**: `TestFixMessageListInfiniteLoop` — sibling tool responses no loop (2 y 3 tools), orden correcto, displaced single tool, interleaved assistants |
| `tests/repl/test_state_command.py` | +5 | `TestStateWorkspaceResolution` — verifica resolución con env vars; `TestWriteKeyFindingsDedup` (2) — no duplica mismo finding, diferentes findings sí se acumulan |
| `tests/repl/test_continue_command.py` | +9 | **Nuevo**: `TestContinueOn` (2) — enable + idempotente; `TestContinueOff` (2) — disable + limpia pending; `TestContinueToggle` (3) — toggle on/off/limpia pending; `TestContinueStatus` (1); `TestContinueHandle` (3) — dispatch, toggle sin args, subcomando desconocido |

---

## Cambios de la iteración 3 (post log review cai_85689193)

### Banner visual de Handoff en CLI

**Fichero**: `src/cai/cli.py`

Se añade un banner visual con Rich cuando un agente hace handoff a otro. Antes, las transiciones se mostraban como tool calls normales (`transfer_to_recon_agent`). Ahora se muestra:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Handoff: Red Team Orchestrator → Recon Agent
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Implementado en los 3 puntos de detección de handoff (streaming asyncio.run, streaming fallback event loop, non-streaming Runner.run).

### Comando `/continue` para controlar auto-continue en runtime

**Ficheros**: `src/cai/repl/commands/continue_cmd.py` (nuevo), `src/cai/repl/commands/__init__.py`, `src/cai/cli.py`

Permite activar/desactivar el modo auto-continue durante la sesión sin necesidad de reiniciar con `--continue`:

- `/continue on` — Activa auto-continue
- `/continue off` — Desactiva y limpia pending input
- `/continue status` — Muestra estado actual
- `/continue` (sin args) — Toggle
- Alias: `/cont`

El estado se gestiona via `CONTINUE_STATE` (module-level singleton compartido entre `continue_cmd.py` y `cli.py`), reemplazando las variables locales `continue_mode` y `_auto_continue_input`.

También se añade soporte de comandos `/` en el HITL prompt (Ctrl+C en continue mode), permitiendo ejecutar `/continue off`, `/state show`, etc. sin hacer doble Ctrl+C.

### Mejoras en prompts de agentes (post análisis de log)

**Problemas detectados en log `cai_85689193`**: Orchestrator envió a PrivEsc sin acceso al target, Exploitation abandonó SQLi sin escalar, PrivEsc ejecutó comandos en la máquina atacante.

| Fichero | Cambio |
|---------|--------|
| `system_orchestrator_agent.md` | Reforzado `think()` obligatorio antes de CADA handoff (incluido el primero). Validación obligatoria antes de PrivEsc (verificar acceso al target). Report obligatorio al final. |
| `system_exploitation_agent.md` | Sección de persistencia: no abandonar vectores de ataque confirmados, agotar opciones de escalación antes de hacer handoff. Solo reportar "EXPLOITATION SUCCESS" con objetivo cumplido. |
| `system_privesc_agent.md` | Prerequisite check obligatorio: verificar session_id o credenciales antes de ejecutar. Si no hay acceso, handoff inmediato al Orchestrator. Aviso de que comandos sin session_id se ejecutan localmente. |

---

## Cambios de la iteración 4 (post log review cai_18d32929)

### Fix: Loop infinito Orchestrator→Report (nudge vs can_finish)

**Bug**: Tras Report generar informe y hacer handoff al Orchestrator, este entraba en loop infinito reenviando a Report (6+ ciclos observados). Causa: el nudge `"Continue with your task..."` se inyectaba para TODOS los agentes `isolated_context` sin importar `can_finish`. El Orchestrator (`can_finish=True`) recibía el nudge, interpretaba "debo seguir" por su prompt ("Never stop") y llamaba a Report de nuevo.

| Fichero | Cambio | Motivo |
|---------|--------|--------|
| `src/cai/sdk/agents/run.py` L1163-1168 | **Nudge condicional**: solo se inyecta `"Continue with your task..."` si `can_finish=False` | Agentes que pueden terminar no reciben el empujón; su `message_history` (con briefing del handoff) es suficiente para que el modelo decida |
| `src/cai/sdk/agents/run.py` L1377 | **Propagar** `model._agent_can_finish = getattr(agent, 'can_finish', True)` | El modelo necesita saber si el agente puede terminar para el nudge de empty response |
| `src/cai/sdk/agents/models/openai_chatcompletions.py` L756 | **Empty-response nudge condicional**: añadido `and not getattr(self, '_agent_can_finish', True)` | Modelos thinking (qwen3) que devuelven respuesta vacía solo reciben retry si `can_finish=False` |

### Fix: Instrucciones de terminación en prompt del Orchestrator

**Fichero**: `src/cai/prompts/system_orchestrator_agent.md`

| Cambio | Motivo |
|--------|--------|
| L34: `"Never stop..."` → `"Keep working... then send to Report and end the session as described below."` | Eliminar instrucción absoluta que impedía terminación |
| L63-75: Nueva sección `## CRITICAL: Session Termination` | Instruye al Orchestrator a producir respuesta texto-only (sin tools) tras recibir handoff del Report Agent, señalando fin de sesión |

### Fix: CLI detecta fin de engagement en continue mode

**Fichero**: `src/cai/cli.py` L1762-1769

| Cambio | Motivo |
|--------|--------|
| Condicional en `CONTINUE_STATE.pending_input` | Si `response.final_output` es truthy, `pending_input = None` en vez de auto-inyectar "Continue working...". Muestra banner `"Engagement complete. Auto-continue paused."`. No necesita comprobar nombres de agente: solo agentes con `can_finish=True` pueden producir `final_output` (los `can_finish=False` son interceptados por `_maybe_force_handoff`) |

### Fix: Duplicación de `user_message` en log JSONL

**Bug**: Instrucciones HITL del usuario (e.g. "Sorry i prefer now LFI") aparecían duplicadas en el log como evento `user_message` — una vez al inyectarse en el Orchestrator y otra al inyectarse en el siguiente agente tras handoff. Causa: `original_input` persiste entre handoffs, y cada agente aislado que no tiene el mensaje en su historial lo re-inyecta y re-loguea.

**Fichero**: `src/cai/sdk/agents/run.py` L1132, L1149-1151

| Cambio | Motivo |
|--------|--------|
| L1132: añadido `and not msg.get("_hitl_logged")` al check | Filtra mensajes ya logueados en handoffs anteriores |
| L1149-1151: `msg["_hitl_logged"] = True` tras `log_user_message()` | Marca el dict in-place en `original_input` para que no se re-loguee en agentes posteriores. La inyección en `message_history` de cada agente sigue ocurriendo (correcta) |

### Fix: Cálculo de contexto unificado con Ollama API

**Bug**: `get_model_input_tokens()` en `util.py` usaba un diccionario hardcodeado (`"qwen2.5": 32000`) que no coincidía con los valores reales de Ollama (`context_length: 32768`), no incluía qwen3 (caía al fallback de gpt: 128000), y era un sistema paralelo a `_get_model_max_tokens()` en `openai_chatcompletions.py` que sí consultaba Ollama. Además, en turnos de tool output (sin llamada al modelo), el porcentaje de contexto se mostraba como `0.0%` en vez de mantener el último valor conocido.

**Fichero**: `src/cai/util.py`

| Cambio | Motivo |
|--------|--------|
| `get_model_input_tokens()` delega a `_get_model_max_tokens()` | Unifica ambos sistemas: consulta Ollama `/api/show`, cachea resultado. Fallback al diccionario hardcodeado (actualizado con qwen3: 40960) solo si el import falla por circular dependency durante la carga de módulos |
| `_create_token_display()` y call sites: retener último `context_pct` cuando `interaction_input_tokens == 0` | En turnos de tool output no hay llamada al modelo, así que `interaction_input_tokens=0`. Antes mostraba `Context: 0.0%`. Ahora mantiene el último porcentaje calculado usando un atributo de función (`_last_context_pct`) |

---

## Mejoras en `execute_code` y auto-compact con contexto aislado

### `src/cai/tools/reconnaissance/exec_code.py`

| Cambio | Motivo |
|--------|--------|
| Sanitización de `filename` con `os.path.basename()` + regex + `shlex.quote()` en todos los comandos | **Seguridad crítica**: el parámetro `filename` se usaba directamente en comandos shell sin sanitizar, permitiendo inyección de comandos (ej: `; rm -rf /`) |
| Verificación de errores de compilación antes de ejecutar | Para lenguajes compilados (Rust, C, C++, Java, Kotlin, C#, Go), el resultado de compilación se ignoraba. Si fallaba, se ejecutaba un binario inexistente o antiguo |
| Alias de lenguaje faltantes en dict `extensions` (`py`, `sh`, `rb`, `pl`, `rs`, `kt`) | Llamar `execute_code(language="py")` creaba `exploit.txt` (extensión incorrecta) pero se ejecutaba como Python. Ahora crea `exploit.py` |
| Delimitador heredoc único con UUID en lugar de `EOF` fijo | Si el código contenía una línea literal `EOF`, el heredoc se cortaba prematuramente. Ahora usa `CAI_CODE_BLOCK_{uuid}` |
| Check de error de creación de fichero más específico | El check `if "error" in result.lower()` se activaba con paths legítimos como `/usr/share/error-handler/`. Ahora verifica `No such file`, `Permission denied` o exit code no-cero |

### `src/cai/tools/reconnaissance/generic_linux_command.py`

| Cambio | Motivo |
|--------|--------|
| Añadidos binarios interactivos faltantes a `_looks_interactive`: `msfconsole`, `vim`, `vi`, `nano`, `emacs`, `top`, `htop`, `atop`, `tmux`, `screen` | Estos comandos interactivos no se detectaban, pudiendo causar bloqueos al ejecutarse sin timeout de sesión interactiva |

### `src/cai/sdk/agents/models/openai_chatcompletions.py`

| Cambio | Motivo |
|--------|--------|
| Auto-compact pasa `history_override=list(self.message_history)` a `_ai_summarize_history()` | **Bug crítico**: `_ai_summarize_history(agent_name)` buscaba en AGENT_MANAGER, pero para agentes con `isolated_context=True`, la referencia se rompe en `_inject_handoff_context` L304 (`to_agent.model.message_history = []`). El resumen se generaba de un historial vacío/desactualizado |
| Auto-compact guarda `COMPACTED_SUMMARIES[name] = [summary]` (lista) + `APPLIED_MEMORY_IDS` | Antes guardaba como string. El resto del sistema espera lista; si se hacía auto-compact seguido de `/memory apply`, el `.append()` sobre string causaba `AttributeError` |
| Constante `AUTO_COMPACT_BRIEFING_PROMPT` con formato de briefing estructurado | El prompt genérico producía prosa libre. El nuevo prompt genera secciones compatibles con briefings de handoff (Objective, User Instructions, Commands Executed, Key Findings, Current Status, Next Steps) |

### `src/cai/repl/commands/memory.py`

| Cambio | Motivo |
|--------|--------|
| `_ai_summarize_history()` acepta `history_override` y `prompt_override` opcionales | Permite al auto-compact pasar el historial correcto del modelo (no el de AGENT_MANAGER) y un prompt especializado para formato briefing. Retrocompatible: ambos parámetros son `Optional` con default `None` |

---

## Servidor MCP de OWASP ZAP (alternativa libre a Burp Suite)

**Por qué**: Burp Suite Professional es de pago. OWASP ZAP es el escáner web open-source equivalente y expone una API REST completa. Se añadió un servidor MCP análogo al de Burp para que cualquier usuario pueda hacer DAST sin licencia.

### `examples/mcp/zap_example/server.py` (nuevo) + `README.md` (nuevo)

Servidor MCP que expone la API REST de ZAP como herramientas MCP. Implementa **11 herramientas**:

| Herramienta | Función |
|-------------|---------|
| `zap_scan` | Lanza escaneo activo o pasivo (`scan_type`) |
| `zap_scan_status` | Progreso del escaneo activo por `scan_id` |
| `zap_spider` | Crawling tradicional con `max_depth` |
| `zap_spider_status` | Progreso del spider |
| `zap_get_alerts` | Lista de alertas/vulnerabilidades detectadas |
| `zap_get_alert_details` | Detalle de una alerta (request/response, evidencia) |
| `zap_sitemap` | Mapa del sitio descubierto (filtrable por `url_prefix`) |
| `zap_ajax_spider` | Spider AJAX para SPAs con JS |
| `zap_ajax_spider_status` | Estado del spider AJAX |
| `zap_add_to_context` | Añade una URL/regex al contexto de ZAP |
| `zap_generate_report` | Genera informe HTML/XML/JSON |

Configurable via `ZAP_API_URL` (default `http://localhost:8080`) y `ZAP_API_KEY`.

**Fix `c357117` — coerción defensiva de tipos**: todos los parámetros aceptan `int | str` con coerción interna. Los modelos pequeños a veces envían un `scan_id` como string `"3"` o un `max_depth` como `"5"`; sin la coerción, ZAP rechazaba la llamada. Las firmas usan `int | str` y normalizan dentro de cada handler.

### `src/cai/repl/commands/memory.py` — Summary Agent usa el backend Ollama (`8b36379`)

| Cambio | Motivo |
|--------|--------|
| El cliente del Summary Agent (usado por `/compact` y auto-compact) se construye con `OLLAMA_API_BASE` cuando está definido (`base_url` con sufijo `/v1`) | **Bug**: el Summary Agent siempre apuntaba a la API de OpenAI. Con un setup 100% local (Ollama), la compactación fallaba o intentaba llamar a OpenAI sin credenciales. Ahora respeta el backend activo |

### `src/cai/repl/commands/memory.py` — reset del historial antes de resumir (`4a4cd38`)

| Cambio | Motivo |
|--------|--------|
| `AGENT_MANAGER.clear_history("Summary Agent")` antes de cada compactación | **Bug**: `OpenAIChatCompletionsModel.__init__` hereda el `message_history` del `AGENT_MANAGER` por nombre de agente. Sin el reset, cada compactación sucesiva acumulaba los pares `"summarize: ..."` / `"<summary>"` de compactaciones anteriores, inflando el prompt del Summary Agent en cada ciclo |

---

## Herramientas web nativas de explotación

**Por qué**: Los agentes dependían de binarios externos (sqlmap, curl manual) para vulnerabilidades web. Para tareas como manipular un JWT o construir un payload LFI, escribir el código a mano vía `execute_code` es propenso a errores en modelos pequeños. Se añadieron **toolkits nativos** (`@function_tool`) que encapsulan la lógica correcta y devuelven resultados estructurados.

### `src/cai/tools/web/xss.py` (nuevo) — XSS (`e7cb286`)

| Herramienta | Función |
|-------------|---------|
| `generate_xss_payloads(category, limit)` | Catálogo de payloads XSS por categoría (basic, attribute, js-context, svg, polyglot…) |
| `reflected_xss_probe(url, param, ...)` | Inyecta payloads en un parámetro y detecta reflexión sin sanitizar |
| `dalfox_command(...)` | Construye la invocación de dalfox con flags correctos |
| `xsstrike_command(...)` | Construye la invocación de XSStrike |

Helper interno `encode_xss_payload(payload, encoding)` (url/html/unicode/base64) para evasión de filtros.

**Tool profiles asociados** (nuevos): `dalfox.py` y `xsstrike.py` — `idle_timeout=60`, `max_execution_time=600`, con `help_indicators` para detectar páginas de ayuda. Ambos usan `command_pattern()`.

### `src/cai/tools/web/jwt.py` (nuevo) — JSON Web Tokens (`ac05eff`, `16d3138`, `066d63c`)

| Herramienta | Función |
|-------------|---------|
| `jwt_decode(token)` | Decodifica header + payload sin verificar firma |
| `jwt_none_alg(token)` | Genera variante con `alg: none` (CVE clásico de bypass de firma) |
| `jwt_modify_header(token, header_changes, alg_none)` | Modifica campos del header (ej: `kid`, `jku`) y re-firma o pone `alg:none` |
| `jwt_modify_claims(token, claims, alg_none)` | Modifica claims del payload (ej: `admin=true`, `sub`) |
| `jwt_brute_hs256(token, wordlist_path, max_words)` | Fuerza bruta del secreto HS256 contra una wordlist |
| `jwt_alg_confusion(token, public_key_path)` | Ataque RS256→HS256 firmando con la clave pública como secreto HMAC |

**Fix `066d63c`**: `_b64url_decode` rechaza caracteres fuera del alfabeto base64url con un diagnóstico claro en vez de devolver bytes corruptos silenciosamente (relacionado con los hallazgos del eval JWT `kid`).

### `src/cai/tools/web/lfi.py` (nuevo) — Local File Inclusion (`ac05eff`, `a386c27`)

| Herramienta | Función |
|-------------|---------|
| `generate_lfi_payloads(...)` | Catálogo de payloads LFI: traversal, `php://filter`, `data://`, wrappers `zip://` y `phar://` (`a386c27`) |
| `lfi_probe(url, param, ...)` | Inyecta payloads y detecta lectura de ficheros (`/etc/passwd`, etc.) |
| `php_filter_payload(file_path, encoding)` | Construye payload `php://filter` para exfiltrar fuentes PHP |
| `decode_php_filter_response(body)` | Decodifica la respuesta base64 de un `php://filter` |

### `src/cai/tools/web/upload.py` (nuevo) — File Upload (`ac05eff`, `7dddb60`)

| Herramienta | Función |
|-------------|---------|
| `generate_upload_bypass_payloads()` | Trucos de bypass de validación (doble extensión, MIME spoofing, null byte, etc.) |
| `generate_polyglot_php(out_path, ...)` | Genera un fichero políglota PHP con **magic bytes multi-formato** (GIF/JPEG/PNG/PDF) que pasa validaciones de tipo (`7dddb60`) |
| `build_upload_curl(...)` | Construye el `curl` multipart para subir el fichero |
| `htaccess_payload(extension)` | Genera un `.htaccess` que fuerza la ejecución de la extensión indicada como PHP |

### `src/cai/agents/exploitation.py` — toolkit conmutable

**Estado actual**: el agente de explotación importa los 4 toolkits web (XSS, JWT, LFI, upload) pero solo **upload está activo**; XSS/JWT/LFI quedan importados y comentados en el bloque `tools=[]`. El diseño es deliberadamente **conmutable por escenario**: para enfocar al modelo pequeño en una sola clase de vulnerabilidad (evita dispersión de tool calls), se descomenta el import + la entrada en `tools=[]` del toolkit deseado. El historial de commits refleja estas conmutaciones (`16d3138` JWT, `22a71da` LFI, `21aa183`/`7dddb60` upload-only).

### `src/cai/tools/reconnaissance/tool_profiles/sqlmap.py` — ajustes (`e7cb286`, `16d3138`)

| Cambio | Motivo |
|--------|--------|
| `max_execution_time` 300 → 900 | Extracción de tablas grandes con time-based blind necesitaba más margen |
| **Skip de smart_defaults si `--tamper`** está presente | Con un tamper script el punto de inyección va codificado dentro del tamper (ej: JWT `kid` via tamper custom); añadir `--forms --crawl=2` distorsiona el escaneo |

---

## Robustez del runtime y de los prompts (iteración final)

### `src/cai/sdk/agents/models/openai_chatcompletions.py` — calibración de tiktoken (`b4903ba`)

| Cambio | Motivo |
|--------|--------|
| **Nueva función** `_token_estimate_multiplier()` + aplicación al estimar tokens | tiktoken (`cl100k_base`) **infraestima** los tokens reales de los modelos Ollama (qwen) en ~30-50%. El porcentaje de contexto mostrado y el threshold de auto-compact se calculaban bajos → auto-compact se disparaba tarde. La estimación se escala por `1.4` cuando hay backend Ollama (`1.0` en cloud). Override via `CAI_TOKEN_ESTIMATE_MULTIPLIER` |

### `src/cai/sdk/agents/models/openai_chatcompletions.py` — guardrail de narrative drift (`9e0ec86`)

| Cambio | Motivo |
|--------|--------|
| **Ampliado** el nudge de especialistas para cubrir dos modos de fallo | Antes solo se reintentaba ante respuesta vacía (qwen3 gastando tokens en `<think>`). Ahora también cubre **narrative drift**: un especialista (`can_finish=False`) que devuelve **prosa describiendo lo que haría** sin emitir ningún tool call. En ambos casos se reintenta una vez con un nudge que exige un tool call. Solo se activa para especialistas |

### `src/cai/sdk/agents/_run_impl.py` — extractor prefiere handoffs (`b84e138`)

| Cambio | Motivo |
|--------|--------|
| Cuando el modelo emite **varias** tool calls estilo Python en una respuesta, el extractor devuelve el **último handoff** si lo hay, en vez del primer match | Los modelos a veces escriben `think(...)` seguido de `transfer_to_recon_agent()`. El handoff expresa la intención operativa real y debe ganar sobre el preámbulo reflexivo (`think`) que lo precede |

### `src/cai/tools/reconnaissance/tool_profiles/__init__.py` — matching de rutas absolutas (`9e5432f`)

| Cambio | Motivo |
|--------|--------|
| **Ampliada** `command_pattern()` para matchear binarios invocados por **ruta absoluta** (`/home/user/go/bin/dalfox`) y como script (`python3 xsstrike.py`) | Herramientas instaladas en `$GOPATH/bin` o ejecutadas por path no se reconocían → no se aplicaban sus perfiles. El nuevo regex añade el ancla `/` (fin de path) y `python[0-9.]*`, sin matchear el nombre como componente intermedio de un path |

### `src/cai/repl/commands/mcp.py` — `/mcp add` muta la lista in-place (`bcf247d`)

| Cambio | Motivo |
|--------|--------|
| `agent.tools[:] = [...]` (slice assignment) en vez de `agent.tools = [...]` | **Bug**: los agentes clonados comparten la lista `tools` por shallow-copy de `dataclasses.replace`. Reasignar creaba una lista nueva solo para una referencia; las herramientas MCP no aparecían en el resto de la cadena de handoffs. La mutación in-place las propaga a todas las referencias |

### `src/cai/tools/reconnaissance/exec_code.py` — chequeo de sintaxis previo (`7d50d01`)

| Cambio | Motivo |
|--------|--------|
| **Diccionario** `_SYNTAX_CHECK` con linters por lenguaje + `compile()` in-process para Python antes de ejecutar | Errores de sintaxis solo se descubrían tras lanzar el intérprete, gastando un turno. Ahora se devuelve `SyntaxError` con línea/columna y el fichero se guarda pero NO se ejecuta |
| **Echo del path guardado**: banner `[execute_code] saved: <abs_path>` | El agente no sabía dónde quedaba el fichero para reutilizarlo en `generic_linux_command` posteriores. Ahora se imprime la ruta absoluta resuelta con `_get_workspace_dir()` |

### `src/cai/sdk/agents/models/openai_chatcompletions.py` — robustez de `items_to_messages`

| Cambio | Motivo |
|--------|--------|
| **Marcador interno permitido** en `EasyInputMessageParam`: `_EASY_INPUT_INTERNAL_KEYS = {"_hitl_logged"}` (`f1bc76b`) | El marcador `_hitl_logged` (anti-duplicación de logs HITL) se adjuntaba a mensajes `EasyInputMessageParam`, que solo admiten `{content, role}`. La validación lo rechazaba. Ahora se whitelist el marcador interno |
| **Diagnóstico** de forma de item inválida antes de lanzar `UserError` (`21aa183`) | Cuando `items_to_messages` recibía un item con forma inesperada, el error no decía cuál. Ahora se loguea `role`/`type`/`keys` del item ofensor antes de propagar el error |

### Prompts de agentes (iteración final)

| Fichero | Cambio | Commit |
|---------|--------|--------|
| `system_orchestrator_agent.md` | **EXACTAMENTE UN tool call por respuesta, nunca cero**; endurecido el routing y la validación previa a PrivEsc | `fd59a2d`, `22a71da` |
| `system_report/strategy/orchestrator…` | Regla **"ONE tool at a time"** propagada al resto de agentes hub-and-spoke | `7bd7d7a` |
| `system_exploitation_agent.md` | `read_key_findings` obligatorio al entrar + regla anti-loop; documentación de los toolkits nativos JWT/LFI/upload y workflow de stored-XSS; toolkit LFI por defecto | `98ed5fe`, `dc1b9d6`, `22a71da` |
| `system_recon_agent.md` / `system_exploitation_agent.md` | Regla "sin rutas hardcodeadas" ampliada + disciplina de `pwd`; la regla de **ruta absoluta aplica solo a FICHEROS, no a binarios** de herramientas (un binario en `$PATH` no debe escribirse con ruta absoluta) | `ff6740a`, `fc9ada7` |
| `system_recon_agent.md` / `system_exploitation_agent.md` | Guía de uso de los servidores MCP (ZAP/Burp) en los prompts | `9e5432f`, `b4835a0` |

---

## Documentación añadida (ficheros nuevos)

| Fichero | Contenido |
|---------|-----------|
| `GUIA_CAI.md` | Guía técnica de uso de la fork: arranque, patrones multi-agente, comandos REPL (`/state`, `/continue`), servidor MCP de ZAP y fixes de compactación (`d0e2763`, `c928cf3`) |
| `GUIA_XSS_MCP.md` | Guía específica del flujo de XSS con el servidor MCP de ZAP (`c357117`) |

---

## Resumen de impacto

| Categoría | Ficheros nuevos | Ficheros modificados | Tests |
|-----------|:-:|:-:|:-:|
| Agentes (Red Team + BB) | 12 | 1 (`exploitation`) | 9 |
| Patrones de orquestación | 4 | 1 | 6 |
| Prompts | 12 | 12 | 0 |
| Tool Profiles (registry + 16 perfiles, +`dalfox`/`xsstrike`) | 17 | 6 | 45+17+8+16+7+5 |
| Servidores MCP (Burp Suite + OWASP ZAP) | 4 | 0 | 0 |
| Herramientas web nativas (`xss`, `jwt`, `lfi`, `upload`) | 4 | 0 | test_xss/jwt/lfi/upload |
| SDK Core (`_run_impl`, `openai_chatcompletions`, `run`, `agent`, `repetition_detector`, `util`) | 1 | 5 | 39+30+4+9+3+1+12+16+20+5 |
| REPL (comandos `/state`, `/continue`, `/mcp`, `memory`) | 2 | 3 | 10+3+9 |
| Factory + registro (`factory`, `__init__`) | 0 | 2 | 0 |
| CLI | 0 | 1 | 0 |
| Herramientas (`generic_linux_command`, `common`, `filesystem`, `web_pentester`, `reasoning`, `exec_code`) | 0 | 6 | 0 |
| Documentación (`GUIA_CAI.md`, `GUIA_XSS_MCP.md`) | 2 | 0 | — |
| Testing infraestructura | 10 | 0 | — |
| **Total** | **~75** | **~35** | **300+** |
