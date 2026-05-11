#include <napi.h>

#include "secdat-sdk.h"

namespace {

struct OwnedOptions {
    std::string dir;
    std::string domain;
    std::string store;
    struct secdat_sdk_options raw;

    OwnedOptions() : raw{NULL, NULL, NULL} {}
};

OwnedOptions ParseOptions(const Napi::Env &env, const Napi::Value &value, bool *ok)
{
    OwnedOptions options;
    *ok = true;

    if (value.IsUndefined() || value.IsNull()) {
        return options;
    }
    if (!value.IsObject()) {
        Napi::TypeError::New(env, "options must be an object").ThrowAsJavaScriptException();
        *ok = false;
        return options;
    }

    Napi::Object object = value.As<Napi::Object>();
    if (object.Has("dir")) {
        if (!object.Get("dir").IsString()) {
            Napi::TypeError::New(env, "options.dir must be a string").ThrowAsJavaScriptException();
            *ok = false;
            return options;
        }
        options.dir = object.Get("dir").As<Napi::String>().Utf8Value();
        options.raw.dir = options.dir.c_str();
    }
    if (object.Has("domain")) {
        if (!object.Get("domain").IsString()) {
            Napi::TypeError::New(env, "options.domain must be a string").ThrowAsJavaScriptException();
            *ok = false;
            return options;
        }
        options.domain = object.Get("domain").As<Napi::String>().Utf8Value();
        options.raw.domain = options.domain.c_str();
    }
    if (object.Has("store")) {
        if (!object.Get("store").IsString()) {
            Napi::TypeError::New(env, "options.store must be a string").ThrowAsJavaScriptException();
            *ok = false;
            return options;
        }
        options.store = object.Get("store").As<Napi::String>().Utf8Value();
        options.raw.store = options.store.c_str();
    }

    return options;
}

Napi::Value Get(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    unsigned char *value = NULL;
    size_t value_length = 0;
    int unsafe_store = 0;
    bool ok;

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "get(keyref, options?) expects a string keyref").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 1 ? info[1] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    std::string keyref = info[0].As<Napi::String>().Utf8Value();
    if (secdat_sdk_get(&options.raw, keyref.c_str(), &value, &value_length, &unsafe_store) != 0) {
        Napi::Error::New(env, "secdat_sdk_get failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object result = Napi::Object::New(env);
    result.Set("value", Napi::Buffer<unsigned char>::Copy(env, value, value_length));
    result.Set("unsafeStore", Napi::Boolean::New(env, unsafe_store != 0));
    secdat_sdk_free(value);
    return result;
}

Napi::Value Set(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;
    bool unsafe_store = false;
    std::string string_value;
    const unsigned char *payload = NULL;
    size_t payload_length = 0;

    if (info.Length() < 2 || !info[0].IsString() || (!info[1].IsString() && !info[1].IsBuffer())) {
        Napi::TypeError::New(env, "set(keyref, value, options?, unsafeStore?) expects a keyref and string or Buffer value").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 2 ? info[2] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }
    if (info.Length() > 3) {
        if (!info[3].IsBoolean()) {
            Napi::TypeError::New(env, "unsafeStore must be a boolean").ThrowAsJavaScriptException();
            return env.Null();
        }
        unsafe_store = info[3].As<Napi::Boolean>().Value();
    }

    if (info[1].IsBuffer()) {
        Napi::Buffer<unsigned char> buffer = info[1].As<Napi::Buffer<unsigned char>>();
        payload = buffer.Data();
        payload_length = buffer.Length();
    } else {
        string_value = info[1].As<Napi::String>().Utf8Value();
        payload = reinterpret_cast<const unsigned char *>(string_value.data());
        payload_length = string_value.size();
    }

    std::string keyref = info[0].As<Napi::String>().Utf8Value();
    if (secdat_sdk_set(&options.raw, keyref.c_str(), payload, payload_length, unsafe_store ? 1 : 0) != 0) {
        Napi::Error::New(env, "secdat_sdk_set failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value Exists(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    int exists = 0;
    bool ok;

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "exists(keyref, options?) expects a string keyref").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 1 ? info[1] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    std::string keyref = info[0].As<Napi::String>().Utf8Value();
    if (secdat_sdk_exists(&options.raw, keyref.c_str(), &exists) != 0) {
        Napi::Error::New(env, "secdat_sdk_exists failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return Napi::Boolean::New(env, exists != 0);
}

Napi::Value CollectStatus(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    struct secdat_sdk_status_summary summary;
    bool ok;

    OwnedOptions options = ParseOptions(env, info.Length() > 0 ? info[0] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    if (secdat_sdk_collect_status(&options.raw, &summary) != 0) {
        Napi::Error::New(env, "secdat_sdk_collect_status failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object result = Napi::Object::New(env);
    result.Set("storeCount", Napi::Number::New(env, static_cast<double>(summary.store_count)));
    result.Set("visibleKeyCount", Napi::Number::New(env, static_cast<double>(summary.visible_key_count)));
    result.Set("wrappedMasterKeyPresent", Napi::Boolean::New(env, summary.wrapped_master_key_present != 0));
    result.Set("keySource", Napi::Number::New(env, summary.key_source));
    result.Set("effectiveSource", Napi::Number::New(env, summary.effective_source));
    result.Set("sessionExpiresAt", Napi::Number::New(env, static_cast<double>(summary.session_expires_at)));
    result.Set("relatedDomainRoot", Napi::String::New(env, summary.related_domain_root));
    return result;
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports.Set("get", Napi::Function::New(env, Get));
    exports.Set("set", Napi::Function::New(env, Set));
    exports.Set("exists", Napi::Function::New(env, Exists));
    exports.Set("collectStatus", Napi::Function::New(env, CollectStatus));
    return exports;
}

}  // namespace

NODE_API_MODULE(secdat_sdk, Init)