# AI Connector

Standalone AI connector module providing OpenAI-compatible API server with multi-provider support.

## Features

- **OpenAI-compatible API** - Works with standard OpenAI client libraries
- **Multi-provider support** - OpenAI, Ollama, Anthropic
- **Rate limiting** - Built-in rate limiting middleware
- **Quota management** - Track and limit API usage
- **Easy configuration** - Environment-based configuration

## Directory Structure

```
ai-connector/
├── src/
│   ├── api/           # HTTP server and routes
│   ├── providers/     # AI provider implementations
│   ├── middleware/    # Rate limiting, quota
│   ├── config/        # Configuration loader
│   └── lib/           # Shared utilities
├── config/
│   └── config.json    # Provider configuration
├── .env.example       # Environment template
└── package.json       # Dependencies
```

## Quick Start

1. Copy environment file:
   ```bash
   cp .env.example .env
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure your AI provider in `.env` or `config/config.json`

4. Start the server:
   ```bash
   npm start
   ```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Chat completions (OpenAI-compatible) |
| `/v1/models` | GET | List available models |
| `/v1/providers` | GET | List configured providers |
| `/health` | GET | Health check |

## Configuration

### Environment Variables

Set in `.env`:
- `OPENAI_API_KEY` - OpenAI API key
- `OPENAI_ENDPOINT` - OpenAI endpoint URL
- `DEFAULT_MODEL` - Default model name
- `PORT` - Server port (default: 3001)
- `HOST` - Server host (default: localhost)

### Provider Configuration

Edit `config/config.json` to configure multiple providers with priorities.

## License

MIT