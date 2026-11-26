# Contributing

1. Keep zero runtime third-party Python dependencies (`stdlib` only) and zero external JS CDNs in `docs/`.
2. Maintain native English and Brazilian Portuguese copy in `src/agent_mcp_guard/i18n.py` and `docs/app.js`.
3. Never commit real credentials or em-dash (`\u2014`) characters anywhere in the repository.
4. Run full local verification before opening a pull request:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
node --check docs/app.js
node tests/test_web_engine.mjs
```
