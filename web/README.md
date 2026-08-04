# idarem web client

React and TypeScript client for the idarem IDA plugin. The production build is
served by the plugin from `web/dist`; the Vite server is only needed during
frontend development.

```sh
npm ci
npm run dev
```

The development client defaults to `http://localhost:8765`. Start IDA and the
plugin before connecting, then enter the token printed in IDA's Output window.

Checks:

```sh
npm test
npm run lint
npm run build
npm audit --audit-level=high
```

See the project-level [README](../README.md) for installation, configuration,
remote access, and security guidance.
