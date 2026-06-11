# secdat Node Binding

This package exposes a small N-API addon over `libsecdat`.

After installing the `secdat` CLI, create the target domain and store once before using the binding:

```sh
secdat --dir /tmp/example/root domain create
secdat --dir /tmp/example/root/child domain create
secdat --dir /tmp/example/root store create team
secdat --dir /tmp/example/root unlock
```

For non-interactive unlock flows, export `SECDAT_MASTER_KEY_PASSPHRASE` before `secdat unlock`. If you provide `SECDAT_MASTER_KEY`, the addon can use that explicit key source without a session unlock.

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
const secdat = require('secdat-sdk-node');

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

Install or rebuild the addon with `npm install` or `npm run build` after `libsecdat` is installed and visible through `pkg-config`. At runtime, ensure the loader can resolve `libsecdat`, for example with `LD_LIBRARY_PATH` when the shared library is outside the default linker path.