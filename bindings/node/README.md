# secdat Node Binding

This package exposes a small N-API addon over `libsecdat`.

## Surface

The module currently exports:

- `get`
- `set`
- `exists`
- `collectStatus`
- `rm`
- `mv`
- `cp`
- `mask`
- `unmask`
- `unlock`
- `lock`

## Example

```js
const secdat = require('./index');

const root = { dir: '/tmp/example/root', store: 'team' };
const child = { dir: '/tmp/example/root/child', store: 'team' };

secdat.unlock(root);
secdat.set('API_TOKEN', Buffer.from('token-123'), root);
secdat.cp('API_TOKEN', 'API_TOKEN_BACKUP', root);

const result = secdat.get('API_TOKEN_BACKUP', root);
if (result.value.toString('utf8') !== 'token-123' || result.unsafeStore) {
  throw new Error('unexpected secret payload');
}

secdat.mask('API_TOKEN', child);
secdat.unmask('API_TOKEN', child);
secdat.rm('API_TOKEN_BACKUP', root, false);
secdat.lock(root);
```

For local development, build the addon first with `npm run build` and ensure the runtime loader can find `libsecdat`.