Fixtures for the GitHub Action self-test (`.github/workflows/action-test.yml`).

- `clean/` holds a safe skill, which must pass.
- `risky/` holds a defanged malicious skill, which must fail. It uses example.com and contains no working payload.
