{
  "targets": [
    {
      "target_name": "secdat_sdk",
      "sources": ["src/addon.cc"],
      "cflags": ["<!@(pkg-config --cflags-only-other libsecdat)"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!@(pkg-config --cflags-only-I libsecdat | sed 's/^-I//')"
      ],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "libraries": ["<!@(pkg-config --libs-only-L --libs-only-l libsecdat)"],
      "ldflags": ["<!@(pkg-config --libs-only-other libsecdat)"]
    }
  ]
}