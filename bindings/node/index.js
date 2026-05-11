const addon = require('./build/Release/secdat_sdk.node');

module.exports = {
  get: addon.get,
  set: addon.set,
  exists: addon.exists,
  collectStatus: addon.collectStatus,
};