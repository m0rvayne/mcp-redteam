# Лучшие практики MCP-серверов

**Версия:** 1.0
**Спецификация MCP:** 2025-03-26
**Последнее обновление:** 7 июня 2026

---

## Содержание

1. [Золотые правила](#1-золотые-правила)
2. [Архитектура и транспорт](#2-архитектура-и-транспорт)
3. [Паттерны кода](#3-паттерны-кода)
4. [Безопасность](#4-безопасность)
5. [Стабильность](#5-стабильность)
6. [Отладка](#6-отладка)
7. [Выбор фреймворка](#7-выбор-фреймворка)
8. [Чек-лист перед релизом](#8-чек-лист-перед-релизом)

---

## 1. Золотые правила

| # | Правило | Почему |
|---|---------|--------|
| 1 | **stdout = ТОЛЬКО JSON-RPC** | Любой `print()` убивает соединение мгновенно |
| 2 | **Tool errors -> isError=True, никогда raise** | Необработанное исключение крашит весь процесс |
| 3 | **Signal handling (SIGTERM/SIGINT)** | Claude Desktop шлёт SIGTERM при закрытии |
| 4 | **HTTP-клиенты — переиспользовать** | Новый AsyncClient на каждый запрос = утечка соединений |
| 5 | **Таймауты на ВСЕ исходящие запросы** | Без таймаута = зависший сервер навсегда |
| 6 | **Абсолютные пути везде** | CWD Claude Desktop = `/` на macOS |
| 7 | **Тяжёлые ресурсы — кэшировать** | Browser, ML-модель, auth — инициализировать один раз |
| 8 | **Валидация путей через is_relative_to()** | Защита от path traversal |
| 9 | **Валидация URL перед fetch** | Защита от SSRF |
| 10 | **Не возвращать str(e) клиенту** | Утечка путей, токенов, внутренних деталей |

---

## 2. Архитектура и транспорт

### stdio (для Claude Desktop / Claude Code)

- Клиент запускает сервер как subprocess
- stdin/stdout = JSON-RPC, stderr = логи
- Клиент управляет lifecycle: launch -> communicate -> close stdin -> SIGTERM -> SIGKILL
- **Правило:** ничего кроме JSON-RPC в stdout

### Streamable HTTP (для удалённых серверов)

- Сервер — независимый процесс с HTTP endpoint
- POST для JSON-RPC, GET для SSE-стримов
- Поддержка сессий через `Mcp-Session-Id`
- **SSE (Server-Sent Events) deprecated** с spec 2025-03-26

### Когда что использовать

| Сценарий | Транспорт |
|----------|-----------|
| Локальный инструмент для Claude Desktop | stdio |
| Сервер в Docker/Kubernetes | Streamable HTTP |
| Несколько клиентов одновременно | Streamable HTTP |
| Максимальная совместимость | stdio |

---

## 3. Паттерны кода

### Signal Handler

```python
import signal, sys

def _handle_shutdown(sig, frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)
```

**Важно:** НЕ делать async cleanup в signal handler. `create_task(_cleanup())` + `sys.exit(0)` = cleanup никогда не выполнится (race condition). Просто `sys.exit(0)`.

### Cached HTTP Client

```python
import httpx

_http_client: httpx.AsyncClient | None = None

def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0)
    return _http_client
```

### Stale Client Recovery

```python
async def _request_safe(method, url, **kwargs):
    global _http_client
    client = _get_client()
    try:
        resp = await client.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp
    except (httpx.ConnectError, httpx.PoolTimeout, httpx.RemoteProtocolError):
        try:
            await _http_client.aclose()
        except Exception:
            pass
        _http_client = None
        client = _get_client()
        resp = await client.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp
```

### Error Handling в Tool Handlers

```python
# Raw MCP SDK:
try:
    # tool logic
except Exception as e:
    return [types.TextContent(type="text", text=f"Error: {safe_error(e)}")]

# FastMCP:
try:
    # tool logic
except Exception as e:
    raise ToolError(safe_error(e))
```

### Safe Error (не утекает внутренняя информация)

```python
import re

def safe_error(e: Exception) -> str:
    msg = str(e)
    msg = re.sub(r'/Users/[^\s:]+', '[path]', msg)
    msg = re.sub(r'(key|token|secret|password)=[^\s&]+', r'\1=[REDACTED]', msg, flags=re.I)
    return msg[:500]  # ограничить длину
```

### Subprocess с таймаутом и kill

```python
proc = await asyncio.create_subprocess_exec(
    "command", "arg1", "arg2",
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE
)
try:
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
except asyncio.TimeoutError:
    proc.kill()
    await proc.wait()
    raise ValueError("Command timed out after 60s")
```

**Никогда:** `subprocess.run()` в async handler (блокирует event loop), `shell=True` (command injection).

### Path Traversal Protection

```python
user_path = (BASE_DIR / user_input).resolve()
if not user_path.is_relative_to(BASE_DIR.resolve()):
    return error("Path traversal detected")
```

### URL Validation (SSRF Protection)

```python
from urllib.parse import urlparse

_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0", "[::1]"}

def validate_url(url: str, allowed_hosts: set | None = None) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid scheme: {parsed.scheme}")
    if parsed.hostname in _BLOCKED_HOSTS:
        raise ValueError(f"Blocked host: {parsed.hostname}")
    if allowed_hosts and not any(parsed.hostname == h or parsed.hostname.endswith("." + h) for h in allowed_hosts):
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    return url
```

---

## 4. Безопасность

### Что проверять (checklist)

- [ ] Все файловые пути валидируются через `is_relative_to()`
- [ ] Все URL валидируются перед fetch (scheme + host)
- [ ] `subprocess.run` -> `create_subprocess_exec` (нет shell)
- [ ] Ошибки не утекают пути, токены, внутренние детали
- [ ] Credentials не в коде, не в plaintext config
- [ ] `.env`, `token.json`, `credentials.json` в `.gitignore`
- [ ] Файлы с секретами имеют `chmod 600`
- [ ] Нет `print()` без `file=sys.stderr`

### Известные атаки на MCP (по состоянию на 2026)

1. **Tool Poisoning** — скрытые `<IMPORTANT>` инструкции в описании инструмента
2. **Cross-Server Shadowing** — один MCP-сервер влияет на поведение другого через описания
3. **Rug Pull** — сервер меняет описания инструментов после одобрения
4. **Output Poisoning** — инъекция инструкций в ответах инструментов
5. **SSRF** — заставить сервер обратиться к внутренним сервисам
6. **Path Traversal** — чтение/запись произвольных файлов (76% серверов уязвимы)
7. **Credential Theft** — чтение config/env файлов через другой MCP-сервер

---

## 5. Стабильность

### Что убивает MCP-серверы

| Причина | Как защититься |
|---------|---------------|
| `print()` в stdout | Только `file=sys.stderr` |
| Unhandled exception | try/except в каждом handler |
| Blocking sync в async | `asyncio.to_thread()` или `run_in_executor` |
| HTTP без таймаута | `httpx.AsyncClient(timeout=30.0)` |
| Subprocess без таймаута | `asyncio.wait_for()` + `proc.kill()` |
| Новый HTTP client на каждый запрос | Module-level singleton |
| Сломанный signal handler | Просто `sys.exit(0)`, никакого async |
| venv shebang после перемещения директории | Пересоздать venv: `uv sync` или `python -m venv .venv` |

### Graceful Shutdown последовательность (Claude Desktop)

1. Клиент закрывает stdin
2. Ждёт завершения процесса
3. Шлёт SIGTERM
4. Ждёт
5. Шлёт SIGKILL

---

## 6. Отладка

### Логи Claude Desktop (macOS)

```
~/Library/Logs/Claude/mcp.log              — общий лог всех MCP
~/Library/Logs/Claude/mcp-server-NAME.log  — лог конкретного сервера
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

Браузерный UI для тестирования серверов.

### Claude Code

```bash
claude --debug mcp
```

### Chrome DevTools в Claude Desktop

Файл `~/Library/Application Support/Claude/developer_settings.json`:
```json
{"allowDevTools": true}
```

---

## 7. Выбор фреймворка

### FastMCP (рекомендуется для новых серверов)

- Декоратор `@mcp.tool()` на функцию — и готово
- Автоматическая генерация схемы из type hints
- Pydantic-валидация входных данных
- `ToolError` для структурированных ошибок
- ~5x меньше boilerplate

### Raw MCP SDK

- 1:1 маппинг на wire format
- Полный контроль над протоколом
- Когда нужен кастомный транспорт или нестандартные capabilities

### Node.js (@modelcontextprotocol/sdk)

- `McpServer` класс с `server.tool()` регистрацией
- Типобезопасность через TypeScript
- `process.on("SIGTERM")` для signal handling

---

## 8. Чек-лист перед релизом

```
СТАБИЛЬНОСТЬ
[ ] Signal handling (SIGTERM + SIGINT)
[ ] Все tool handlers в try/except
[ ] Нет print() без file=sys.stderr
[ ] HTTP client reuse (не per-request)
[ ] Таймауты на все HTTP и subprocess
[ ] Нет blocking sync в async handlers

БЕЗОПАСНОСТЬ
[ ] Path traversal: is_relative_to() на все файловые операции
[ ] SSRF: validate_url() на все пользовательские URL
[ ] No shell=True в subprocess
[ ] Error messages не утекают секреты
[ ] Credentials не в коде / не plaintext
[ ] Sensitive files в .gitignore

КАЧЕСТВО
[ ] py_compile / node --check проходит
[ ] Зависимости закреплены (==X.Y.Z)
[ ] venv изолирован от системного Python
[ ] Нет мёртвого кода / неиспользуемых зависимостей
```
