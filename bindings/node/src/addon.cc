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

struct OwnedListFilters {
    std::string include_pattern;
    std::string exclude_pattern;
    struct secdat_sdk_list_filters raw;

    OwnedListFilters() : raw{NULL, NULL, 0, 0, 0} {}
};

struct OwnedDomainFilters {
    std::string pattern;
    struct secdat_sdk_domain_filters raw;

    OwnedDomainFilters() : raw{NULL, 0, 0, 0} {}
};

const char *KeySourceName(int value)
{
    switch (value) {
    case SECDAT_SDK_KEY_SOURCE_ENVIRONMENT:
        return "environment";
    case SECDAT_SDK_KEY_SOURCE_SESSION:
        return "session";
    default:
        return "locked";
    }
}

const char *EffectiveSourceName(int value)
{
    switch (value) {
    case SECDAT_SDK_EFFECTIVE_SOURCE_ENVIRONMENT:
        return "environment";
    case SECDAT_SDK_EFFECTIVE_SOURCE_LOCAL_SESSION:
        return "local_session";
    case SECDAT_SDK_EFFECTIVE_SOURCE_INHERITED_SESSION:
        return "inherited_session";
    case SECDAT_SDK_EFFECTIVE_SOURCE_EXPLICIT_LOCK:
        return "explicit_lock";
    case SECDAT_SDK_EFFECTIVE_SOURCE_BLOCKED:
        return "blocked";
    default:
        return "locked";
    }
}

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

OwnedListFilters ParseListFilters(const Napi::Env &env, const Napi::Value &value, bool *ok)
{
    OwnedListFilters filters;
    *ok = true;

    if (value.IsUndefined() || value.IsNull()) {
        return filters;
    }
    if (!value.IsObject()) {
        Napi::TypeError::New(env, "filters must be an object").ThrowAsJavaScriptException();
        *ok = false;
        return filters;
    }

    Napi::Object object = value.As<Napi::Object>();
    if (object.Has("includePattern")) {
        if (!object.Get("includePattern").IsString()) {
            Napi::TypeError::New(env, "filters.includePattern must be a string").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.include_pattern = object.Get("includePattern").As<Napi::String>().Utf8Value();
        filters.raw.include_pattern = filters.include_pattern.c_str();
    }
    if (object.Has("excludePattern")) {
        if (!object.Get("excludePattern").IsString()) {
            Napi::TypeError::New(env, "filters.excludePattern must be a string").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.exclude_pattern = object.Get("excludePattern").As<Napi::String>().Utf8Value();
        filters.raw.exclude_pattern = filters.exclude_pattern.c_str();
    }
    if (object.Has("safe")) {
        if (!object.Get("safe").IsBoolean()) {
            Napi::TypeError::New(env, "filters.safe must be a boolean").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.raw.safe = object.Get("safe").As<Napi::Boolean>().Value() ? 1 : 0;
    }
    if (object.Has("unsafeStore")) {
        if (!object.Get("unsafeStore").IsBoolean()) {
            Napi::TypeError::New(env, "filters.unsafeStore must be a boolean").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.raw.unsafe_store = object.Get("unsafeStore").As<Napi::Boolean>().Value() ? 1 : 0;
    }
    if (object.Has("sandboxInjectable")) {
        if (!object.Get("sandboxInjectable").IsBoolean()) {
            Napi::TypeError::New(env, "filters.sandboxInjectable must be a boolean").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.raw.sandbox_injectable = object.Get("sandboxInjectable").As<Napi::Boolean>().Value() ? 1 : 0;
    }

    return filters;
}

OwnedDomainFilters ParseDomainFilters(const Napi::Env &env, const Napi::Value &value, bool *ok)
{
    OwnedDomainFilters filters;
    *ok = true;

    if (value.IsUndefined() || value.IsNull()) {
        return filters;
    }
    if (!value.IsObject()) {
        Napi::TypeError::New(env, "filters must be an object").ThrowAsJavaScriptException();
        *ok = false;
        return filters;
    }

    Napi::Object object = value.As<Napi::Object>();
    if (object.Has("pattern")) {
        if (!object.Get("pattern").IsString()) {
            Napi::TypeError::New(env, "filters.pattern must be a string").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.pattern = object.Get("pattern").As<Napi::String>().Utf8Value();
        filters.raw.pattern = filters.pattern.c_str();
    }
    if (object.Has("includeAncestors")) {
        if (!object.Get("includeAncestors").IsBoolean()) {
            Napi::TypeError::New(env, "filters.includeAncestors must be a boolean").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.raw.include_ancestors = object.Get("includeAncestors").As<Napi::Boolean>().Value() ? 1 : 0;
    }
    if (object.Has("includeDescendants")) {
        if (!object.Get("includeDescendants").IsBoolean()) {
            Napi::TypeError::New(env, "filters.includeDescendants must be a boolean").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.raw.include_descendants = object.Get("includeDescendants").As<Napi::Boolean>().Value() ? 1 : 0;
    }
    if (object.Has("includeInherited")) {
        if (!object.Get("includeInherited").IsBoolean()) {
            Napi::TypeError::New(env, "filters.includeInherited must be a boolean").ThrowAsJavaScriptException();
            *ok = false;
            return filters;
        }
        filters.raw.include_inherited = object.Get("includeInherited").As<Napi::Boolean>().Value() ? 1 : 0;
    }

    return filters;
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

Napi::Value Remove(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;
    bool ignore_missing = false;

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "rm(keyref, options?, ignoreMissing?) expects a string keyref").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 1 ? info[1] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }
    if (info.Length() > 2) {
        if (!info[2].IsBoolean()) {
            Napi::TypeError::New(env, "ignoreMissing must be a boolean").ThrowAsJavaScriptException();
            return env.Null();
        }
        ignore_missing = info[2].As<Napi::Boolean>().Value();
    }

    std::string keyref = info[0].As<Napi::String>().Utf8Value();
    if (secdat_sdk_rm(&options.raw, keyref.c_str(), ignore_missing ? 1 : 0) != 0) {
        Napi::Error::New(env, "secdat_sdk_rm failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value Move(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "mv(sourceKeyref, destinationKeyref, options?) expects two string keyrefs").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 2 ? info[2] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    std::string source_keyref = info[0].As<Napi::String>().Utf8Value();
    std::string destination_keyref = info[1].As<Napi::String>().Utf8Value();
    if (secdat_sdk_mv(&options.raw, source_keyref.c_str(), destination_keyref.c_str()) != 0) {
        Napi::Error::New(env, "secdat_sdk_mv failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value Copy(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "cp(sourceKeyref, destinationKeyref, options?) expects two string keyrefs").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 2 ? info[2] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    std::string source_keyref = info[0].As<Napi::String>().Utf8Value();
    std::string destination_keyref = info[1].As<Napi::String>().Utf8Value();
    if (secdat_sdk_cp(&options.raw, source_keyref.c_str(), destination_keyref.c_str()) != 0) {
        Napi::Error::New(env, "secdat_sdk_cp failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value Mask(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "mask(keyref, options?) expects a string keyref").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 1 ? info[1] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    std::string keyref = info[0].As<Napi::String>().Utf8Value();
    if (secdat_sdk_mask(&options.raw, keyref.c_str()) != 0) {
        Napi::Error::New(env, "secdat_sdk_mask failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value Unmask(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "unmask(keyref, options?) expects a string keyref").ThrowAsJavaScriptException();
        return env.Null();
    }

    OwnedOptions options = ParseOptions(env, info.Length() > 1 ? info[1] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    std::string keyref = info[0].As<Napi::String>().Utf8Value();
    if (secdat_sdk_unmask(&options.raw, keyref.c_str()) != 0) {
        Napi::Error::New(env, "secdat_sdk_unmask failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value Unlock(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;

    OwnedOptions options = ParseOptions(env, info.Length() > 0 ? info[0] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    if (secdat_sdk_unlock(&options.raw) != 0) {
        Napi::Error::New(env, "secdat_sdk_unlock failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value Lock(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;

    OwnedOptions options = ParseOptions(env, info.Length() > 0 ? info[0] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    if (secdat_sdk_lock(&options.raw) != 0) {
        Napi::Error::New(env, "secdat_sdk_lock failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
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
    result.Set("keySourceName", Napi::String::New(env, KeySourceName(summary.key_source)));
    result.Set("effectiveSource", Napi::Number::New(env, summary.effective_source));
    result.Set("effectiveSourceName", Napi::String::New(env, EffectiveSourceName(summary.effective_source)));
    result.Set("sessionExpiresAt", Napi::Number::New(env, static_cast<double>(summary.session_expires_at)));
    result.Set("relatedDomainRoot", Napi::String::New(env, summary.related_domain_root));
    return result;
}

Napi::Value ListKeys(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    struct secdat_sdk_key_metadata_list result_list;
    bool ok;

    OwnedOptions options = ParseOptions(env, info.Length() > 0 ? info[0] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }
    OwnedListFilters filters = ParseListFilters(env, info.Length() > 1 ? info[1] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    if (secdat_sdk_list_keys(&options.raw, &filters.raw, &result_list) != 0) {
        Napi::Error::New(env, "secdat_sdk_list_keys failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Array result = Napi::Array::New(env, result_list.count);
    for (size_t index = 0; index < result_list.count; index += 1) {
        const struct secdat_sdk_key_metadata &item = result_list.items[index];
        Napi::Object row = Napi::Object::New(env);
        row.Set("key", Napi::String::New(env, item.key));
        row.Set("store", Napi::String::New(env, item.store));
        row.Set("canonicalKeyref", Napi::String::New(env, item.canonical_keyref));
        row.Set("sourceDomain", Napi::String::New(env, item.source_domain));
        row.Set("sourceType", Napi::String::New(env, item.source_type));
        row.Set("local", Napi::Boolean::New(env, item.local != 0));
        row.Set("inherited", Napi::Boolean::New(env, item.inherited != 0));
        row.Set("unsafeStore", Napi::Boolean::New(env, item.unsafe_store != 0));
        row.Set("storageMode", Napi::String::New(env, item.storage_mode));
        row.Set("keyVisibility", Napi::String::New(env, item.key_visibility));
        row.Set("valueAccess", Napi::String::New(env, item.value_access));
        row.Set("sandboxInject", Napi::String::New(env, item.sandbox_inject));
        result.Set(index, row);
    }
    secdat_sdk_free(result_list.items);
    return result;
}

Napi::Value ListStores(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    struct secdat_sdk_store_metadata_list result_list;
    bool ok;

    OwnedOptions options = ParseOptions(env, info.Length() > 0 ? info[0] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    if (secdat_sdk_list_stores(&options.raw, &result_list) != 0) {
        Napi::Error::New(env, "secdat_sdk_list_stores failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Array result = Napi::Array::New(env, result_list.count);
    for (size_t index = 0; index < result_list.count; index += 1) {
        Napi::Object row = Napi::Object::New(env);
        row.Set("name", Napi::String::New(env, result_list.items[index].name));
        result.Set(index, row);
    }
    secdat_sdk_free(result_list.items);
    return result;
}

Napi::Value ListDomains(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    struct secdat_sdk_domain_metadata_list result_list;
    bool ok;

    OwnedOptions options = ParseOptions(env, info.Length() > 0 ? info[0] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }
    OwnedDomainFilters filters = ParseDomainFilters(env, info.Length() > 1 ? info[1] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }

    if (secdat_sdk_list_domains(&options.raw, &filters.raw, &result_list) != 0) {
        Napi::Error::New(env, "secdat_sdk_list_domains failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Array result = Napi::Array::New(env, result_list.count);
    for (size_t index = 0; index < result_list.count; index += 1) {
        const struct secdat_sdk_domain_metadata &item = result_list.items[index];
        Napi::Object row = Napi::Object::New(env);
        row.Set("root", Napi::String::New(env, item.root));
        row.Set("unlocked", Napi::Boolean::New(env, item.unlocked != 0));
        row.Set("keySource", Napi::Number::New(env, item.key_source));
        row.Set("keySourceName", Napi::String::New(env, KeySourceName(item.key_source)));
        row.Set("effectiveSource", Napi::Number::New(env, item.effective_source));
        row.Set("effectiveSourceName", Napi::String::New(env, EffectiveSourceName(item.effective_source)));
        row.Set("sessionExpiresAt", Napi::Number::New(env, static_cast<double>(item.session_expires_at)));
        row.Set("remainingSeconds", Napi::Number::New(env, static_cast<double>(item.remaining_seconds)));
        row.Set("relatedDomainRoot", Napi::String::New(env, item.related_domain_root));
        row.Set("storeCount", Napi::Number::New(env, static_cast<double>(item.store_count)));
        row.Set("visibleKeyCount", Napi::Number::New(env, static_cast<double>(item.visible_key_count)));
        row.Set("orphanedDomain", Napi::Boolean::New(env, item.orphaned_domain != 0));
        row.Set("wrappedMasterKeyPresent", Napi::Boolean::New(env, item.wrapped_master_key_present != 0));
        result.Set(index, row);
    }
    secdat_sdk_free(result_list.items);
    return result;
}

Napi::Value WaitUnlock(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    bool ok;
    time_t timeout_seconds = 0;

    OwnedOptions options = ParseOptions(env, info.Length() > 0 ? info[0] : env.Undefined(), &ok);
    if (!ok) {
        return env.Null();
    }
    if (info.Length() > 1) {
        if (!info[1].IsNumber()) {
            Napi::TypeError::New(env, "timeoutSeconds must be a number").ThrowAsJavaScriptException();
            return env.Null();
        }
        timeout_seconds = static_cast<time_t>(info[1].As<Napi::Number>().Int64Value());
    }

    if (secdat_sdk_wait_unlock(&options.raw, timeout_seconds) != 0) {
        Napi::Error::New(env, "secdat_sdk_wait_unlock failed; see stderr for details").ThrowAsJavaScriptException();
        return env.Null();
    }
    return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports.Set("get", Napi::Function::New(env, Get));
    exports.Set("set", Napi::Function::New(env, Set));
    exports.Set("exists", Napi::Function::New(env, Exists));
    exports.Set("rm", Napi::Function::New(env, Remove));
    exports.Set("mv", Napi::Function::New(env, Move));
    exports.Set("cp", Napi::Function::New(env, Copy));
    exports.Set("mask", Napi::Function::New(env, Mask));
    exports.Set("unmask", Napi::Function::New(env, Unmask));
    exports.Set("unlock", Napi::Function::New(env, Unlock));
    exports.Set("lock", Napi::Function::New(env, Lock));
    exports.Set("collectStatus", Napi::Function::New(env, CollectStatus));
    exports.Set("listKeys", Napi::Function::New(env, ListKeys));
    exports.Set("listStores", Napi::Function::New(env, ListStores));
    exports.Set("listDomains", Napi::Function::New(env, ListDomains));
    exports.Set("waitUnlock", Napi::Function::New(env, WaitUnlock));
    return exports;
}

}  // namespace

NODE_API_MODULE(secdat_sdk, Init)
