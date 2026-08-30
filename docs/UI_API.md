# UI ↔ engine contract

The UI must remain a thin client. Commands are line-oriented JSON so the native shell can later be replaced without changing the protection engine.

## Request envelope

```json
{"id":"42","command":"inspect","input":"app.exe"}
```

Supported commands:

- `analyze`
- `protect`
- `verify`
- `inspect`

## Events

The engine may emit:

```json
{"id":"42","event":"progress","stage":"analyze","percent":35}
{"id":"42","event":"log","level":"info","message":"analysis complete"}
{"id":"42","event":"result","ok":true}
```

Errors use:

```json
{"id":"42","event":"result","ok":false,"code":"INVALID_INPUT","message":"unsupported artifact"}
```

The contract intentionally contains no password fields in progress/log events. Password handling belongs to the native process and must never be echoed into UI logs.
