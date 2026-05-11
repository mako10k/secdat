const addon = require('./build/Release/secdat_sdk.node');

module.exports = {
  get: addon.get,
  set: addon.set,
  exists: addon.exists,
  rm: addon.rm,
  mv: addon.mv,
  cp: addon.cp,
  mask: addon.mask,
  unmask: addon.unmask,
  unlock: addon.unlock,
  lock: addon.lock,
  collectStatus: addon.collectStatus,
};