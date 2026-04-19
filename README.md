# claude-channel-whatsapp · fork de Elsa

Fork personal del plugin [PenguinMiaou/claude-channel-whatsapp](https://github.com/PenguinMiaou/claude-channel-whatsapp), modificado para alimentar a **Elsa** — la asistente IA de Fer (mi Señor 🐉) — con todo lo que llega por WhatsApp.

> ⚠️ Este fork diverge bastante del upstream: branch `main` mantiene el código original, branch `master` contiene las extensiones de Elsa.

## Qué hace

Plugin de canal para Claude Code que:

1. Conecta a WhatsApp vía [Baileys](https://github.com/WhiskeySockets/Baileys) (bibliotec WhatsApp Web no oficial).
2. Por cada mensaje entrante, **spawnea un `claude -p`** subprocess con el contexto del chat.
3. Captura el `stdout` del subprocess y lo manda de vuelta al chat como respuesta.

Diferencia clave con el original: el plugin **no usa el canal MCP** para entregar mensajes a Claude — los procesa de forma directa con `claude -p`, lo que evita conflictos de allowlist y permite spawn paralelo.

## Extensiones de este fork (vs upstream)

- **🎤 Mirror de modalidad**: si el mensaje entrante es una nota de voz, la respuesta vuelve también como voice note (TTS con `edge-tts es-ES-XimenaNeural`).
- **🗣 STT local con Vosk**: las notas de voz se transcriben antes de pasar a `claude -p`, soporte ES y CA.
- **📎 Sigil ATTACH**: Claude puede adjuntar ficheros locales escribiendo `[[ATTACH:/ruta/absoluta|modo]]` en su respuesta. Modos: `voice` (PTT con waveform), `audio`, `image`, `doc`. Las líneas ATTACH se eliminan del texto antes de enviar.
- **🌊 Waveform real**: las voice notes salientes muestran su forma de onda real (vía `audio-decode`), no la dummy del upstream.
- **💾 Sesiones persistentes por chat**: cada chat mantiene su propia sesión de Claude (`session_id`), guardada en disco para sobrevivir reinicios.
- **🚦 Cola por chat**: turnos serializados — un mensaje no se procesa hasta que termina el anterior del mismo chat.
- **🎬 Presencia "grabando audio…"**: antes de enviar voice notes, simula presencia recording para que el cliente WhatsApp pinte el indicador correcto.

## Estructura

```
.
├── server.ts              # entrypoint Bun: socket Baileys + handler de mensajes + spawn claude -p
├── bin/
│   ├── start.sh           # arranque vía systemd
│   └── transcribe.py      # wrapper Vosk para STT (ES/CA)
├── skills/
│   └── configure/         # skill /whatsapp:configure para emparejar
├── .mcp.json              # declaración del MCP server (mínima — sin caps de canal)
├── .claude-plugin/        # metadatos del plugin Claude Code
├── package.json
└── LICENSE                # MIT
```

## Stack

- **Runtime**: [Bun](https://bun.sh/)
- **WhatsApp**: [@whiskeysockets/baileys](https://www.npmjs.com/package/@whiskeysockets/baileys) `7.0.0-rc.9`
- **MCP**: `@modelcontextprotocol/sdk`
- **Audio**: `audio-decode` (waveform), `edge-tts` (TTS, externo), `vosk-model-small-es-0.42` / `vosk-model-small-ca-0.4` (STT local)
- **Validación**: `zod`

## Instalación

```bash
bun install
```

Configurar token de Telegram/WhatsApp y emparejar via la skill `/whatsapp:configure` desde Claude Code.

Ver `skills/configure/SKILL.md` para los pasos detallados.

## Operación (homelab Elsa)

Corre como `claude-whatsapp.service` (systemd user) en la VM `agents` del Pegasus. Estado/auth en `/home/ferran/.claude/channels/claude-whatsapp/`.

```bash
systemctl --user status claude-whatsapp.service
journalctl --user -u claude-whatsapp.service -f
tail -f ~/.claude/channels/claude-whatsapp/server.log
```

## Configuración del responder

El subprocess `claude -p` se invoca con:

```
--settings ~/.claude/settings-whatsapp-responder.json
--append-system-prompt "<system prompt de Elsa>"
--dangerously-skip-permissions
--output-format text
```

`settings-whatsapp-responder.json` debe deshabilitar el plugin de Telegram (si existe en el host) para evitar que cada `claude -p` levante un bun MCP rival con `getUpdates` paralelo:

```json
{
  "permissions": { "defaultMode": "dontAsk" },
  "enabledPlugins": { "telegram@claude-plugins-official": false },
  "skipDangerousModePermissionPrompt": true
}
```

## Licencia

MIT (heredada del upstream).
