# CloudCrypt Bridge

**Universal Encryption Solution** — Battle-tested since November 18, 2025

## ⚠️ DEMO DISCLAIMER

This is a **DEMO** version. For production, get the code pack: [seekrates-ai.com/cloudcrypt](https://seekrates-ai.com/cloudcrypt)

## Quick Start

```bash
pip install -r requirements.txt
export FERNET_KEY="your-32-character-encryption-key!"
python app.py
```

Visit: http://localhost:5000

## Deploy to Railway

1. Fork repo → Create Railway project → Connect GitHub
2. Add env var: `FERNET_KEY` (32+ chars)
3. Deploy!

## API Endpoints

| Method | Endpoint | Body |
|--------|----------|------|
| GET | /health | - |
| POST | /encrypt | `{"plaintext": "..."}` |
| POST | /decrypt | `{"encrypted": "gAAAAAB..."}` |
| POST | /validate | `{"text": "..."}` |

## Library Usage

```python
from cloudcrypt_bridge import SecretsManager

manager = SecretsManager(master_key='your-32-char-key!')
encrypted = manager.encrypt('sk-proj-abc123...')
plaintext = manager.decrypt(encrypted)
```

## Origin

Born from a 4-week production crisis. Mixed encryption methods caused silent failures. $20K debugging cost. Now: zero failures since Nov 18, 2025.

## TTAP Proof

Generated via Three-Team Autonomous Process (Mohan + D-C + C-C). Same code runs in Seekrates AI production.

## License

MIT — Mohan Iyer (mohan@pixels.net.nz)