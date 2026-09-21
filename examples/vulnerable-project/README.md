# Vulnerable Project (Demo)

This tiny fake project exists only to demonstrate EnvGuard. Every credential
in it is fabricated and not connected to any real service.

Run EnvGuard against it from the EnvGuard project root:

```bash
python main.py examples/vulnerable-project
```

You should see multiple findings (AWS keys, an API key, a hardcoded
password, a database connection string, and a GitHub token), plus a
sensitive-file warning for `.env.example`.
