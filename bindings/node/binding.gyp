{
  "targets": [
    {
      "target_name": "secdat_sdk",
      "sources": ["src/addon.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "../../src"
      ],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "libraries": ["<(module_root_dir)/../../src/.libs/libsecdat.so"],
      "ldflags": ["-Wl,-rpath,<(module_root_dir)/../../src/.libs"]
    }
  ]
}