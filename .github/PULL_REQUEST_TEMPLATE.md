## What changes

Describe the change and why.

## Type of change

- [ ] Bug fix
- [ ] New tool
- [ ] Improvement/refactoring
- [ ] Documentation
- [ ] Infrastructure/Docker

## Checklist

- [ ] `pytest` passes locally
- [ ] If a new tool: dedicated template with ≥500 words
      (`pytest tests/test_tool_pages.py`)
- [ ] If there was a schema change: migration created and reviewed
- [ ] No network calls outside of `SafeHTTPClient`/`resolve_host_ips`
- [ ] New environment variables documented in `.env.example`

## Related issue

Closes #