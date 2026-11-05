# AI Connector Quickstart

Standalone AI connector for OpenAI-compatible API access.

## Prerequisites

- Node.js >= 18.0.0
- AI provider API key (OpenAI, Ollama, or Anthropic)

## Installation

```bash
# Clone/copy the ai-connector directory
cd ai-connector

# Install dependencies
npm install
```

## Configuration

### Option 1: Environment Variables

```bash
cp .env.example .env
# Edit .env with your API keys
```

### Option 2: Config File

Edit `config/config.json` directly.

## Usage

### Start the Server

```bash
npm start
```

Server runs on `http://localhost:3001` by default.

### Test with cURL

```bash
# Check health
curl http://localhost:3001/health

# List models
curl http://localhost:3001/v1/models

# Chat completions
curl -X POST http://localhost:3001/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### Integration with OpenAI Client

```javascript
import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: 'your-api-key',
  baseURL: 'http://localhost:3001/v1'
});

const chat = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello!' }]
});
```

## Multiple Providers

Configure multiple providers in `config/config.json`. Requests are routed based on provider priority (lower number = higher priority).

## Troubleshooting

- **Connection refused**: Check server is running and PORT is correct
- **401 Unauthorized**: Verify API key in `.env`
- **Rate limited**: Wait and retry, or adjust `RATE_LIMIT_REQUESTS`