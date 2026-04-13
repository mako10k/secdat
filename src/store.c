#include "store.h"

#include "i18n.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SECDAT_ENTRY_VERSION 1
#define SECDAT_ENTRY_ALGORITHM_AES_256_GCM 2
#define SECDAT_NONCE_LEN 12
#define SECDAT_TAG_LEN 16
#define SECDAT_HEADER_LEN 16

static const unsigned char secdat_entry_magic[8] = {'S', 'E', 'C', 'D', 'A', 'T', '1', '\0'};

struct secdat_key_list {
    char **items;
    size_t count;
    size_t capacity;
};

static void secdat_secure_clear(void *buffer, size_t length)
{
    if (buffer != NULL && length > 0) {
        OPENSSL_cleanse(buffer, length);
    }
}

static void secdat_key_list_free(struct secdat_key_list *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }

    for (index = 0; index < list->count; index += 1) {
        free(list->items[index]);
    }

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int secdat_key_list_contains(const struct secdat_key_list *list, const char *value)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index], value) == 0) {
            return 1;
        }
    }

    return 0;
}

static int secdat_key_list_append(struct secdat_key_list *list, const char *value)
{
    char **new_items;
    size_t new_capacity;

    if (secdat_key_list_contains(list, value)) {
        return 0;
    }

    if (list->count == list->capacity) {
        new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        new_items = realloc(list->items, sizeof(*new_items) * new_capacity);
        if (new_items == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count] = strdup(value);
    if (list->items[list->count] == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    list->count += 1;
    return 0;
}

static int secdat_compare_strings(const void *left, const void *right)
{
    const char *const *left_string = left;
    const char *const *right_string = right;

    return strcmp(*left_string, *right_string);
}

static int secdat_is_unreserved(unsigned char character)
{
    return isalnum(character) || character == '-' || character == '_' || character == '.';
}

static int secdat_escape_component(const char *input, char **output)
{
    size_t index;
    size_t extra = 0;
    size_t length = strlen(input);
    char *result;
    char *cursor;

    for (index = 0; index < length; index += 1) {
        if (!secdat_is_unreserved((unsigned char)input[index])) {
            extra += 2;
        }
    }

    result = malloc(length + extra + 1);
    if (result == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    cursor = result;
    for (index = 0; index < length; index += 1) {
        if (secdat_is_unreserved((unsigned char)input[index])) {
            *cursor++ = input[index];
            continue;
        }

        snprintf(cursor, 4, "%%%02X", (unsigned char)input[index]);
        cursor += 3;
    }

    *cursor = '\0';
    *output = result;
    return 0;
}

static int secdat_hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int secdat_unescape_component(const char *input, char **output)
{
    size_t length = strlen(input);
    char *result;
    size_t read_index;
    size_t write_index;
    int high;
    int low;

    result = malloc(length + 1);
    if (result == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    read_index = 0;
    write_index = 0;
    while (read_index < length) {
        if (input[read_index] == '%' && read_index + 2 < length) {
            high = secdat_hex_value(input[read_index + 1]);
            low = secdat_hex_value(input[read_index + 2]);
            if (high >= 0 && low >= 0) {
                result[write_index++] = (char)((high << 4) | low);
                read_index += 3;
                continue;
            }
        }

        result[write_index++] = input[read_index++];
    }

    result[write_index] = '\0';
    *output = result;
    return 0;
}

static int secdat_join_path(char *buffer, size_t size, const char *left, const char *right)
{
    int written;

    written = snprintf(buffer, size, "%s/%s", left, right);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_data_home(char *buffer, size_t size)
{
    const char *xdg_data_home = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    int written;

    if (xdg_data_home != NULL && xdg_data_home[0] != '\0') {
        written = snprintf(buffer, size, "%s", xdg_data_home);
    } else if (home != NULL && home[0] != '\0') {
        written = snprintf(buffer, size, "%s/.local/share", home);
    } else {
        fprintf(stderr, _("HOME is not set\n"));
        return 1;
    }

    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_store_root(const char *store_name, char *buffer, size_t size)
{
    char data_home[PATH_MAX];
    char encoded_store[PATH_MAX];
    char *allocated_store = NULL;
    const char *resolved_store = store_name == NULL ? "default" : store_name;
    int written;
    int status;

    status = secdat_escape_component(resolved_store, &allocated_store);
    if (status != 0) {
        return status;
    }

    written = snprintf(encoded_store, sizeof(encoded_store), "%s", allocated_store);
    free(allocated_store);
    if (written < 0 || (size_t)written >= sizeof(encoded_store)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    status = secdat_data_home(data_home, sizeof(data_home));
    if (status != 0) {
        return status;
    }

    written = snprintf(
        buffer,
        size,
        "%s/secdat/domains/by-id/default/stores/%s",
        data_home,
        encoded_store
    );
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_store_entries_dir(const char *store_name, char *buffer, size_t size)
{
    char store_root[PATH_MAX];
    int status;

    status = secdat_store_root(store_name, store_root, sizeof(store_root));
    if (status != 0) {
        return status;
    }

    return secdat_join_path(buffer, size, store_root, "entries");
}

static int secdat_store_tombstones_dir(const char *store_name, char *buffer, size_t size)
{
    char store_root[PATH_MAX];
    int status;

    status = secdat_store_root(store_name, store_root, sizeof(store_root));
    if (status != 0) {
        return status;
    }

    return secdat_join_path(buffer, size, store_root, "tombstones");
}

static int secdat_build_entry_path(const char *store_name, const char *key, char *buffer, size_t size)
{
    char entries_dir[PATH_MAX];
    char *escaped_key = NULL;
    int status;
    int written;

    status = secdat_store_entries_dir(store_name, entries_dir, sizeof(entries_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_escape_component(key, &escaped_key);
    if (status != 0) {
        return status;
    }

    written = snprintf(buffer, size, "%s/%s.sec", entries_dir, escaped_key);
    free(escaped_key);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_build_tombstone_path(const char *store_name, const char *key, char *buffer, size_t size)
{
    char tombstones_dir[PATH_MAX];
    char *escaped_key = NULL;
    int status;
    int written;

    status = secdat_store_tombstones_dir(store_name, tombstones_dir, sizeof(tombstones_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_escape_component(key, &escaped_key);
    if (status != 0) {
        return status;
    }

    written = snprintf(buffer, size, "%s/%s.tomb", tombstones_dir, escaped_key);
    free(escaped_key);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_ensure_directory(const char *path, mode_t mode)
{
    struct stat status;
    char partial[PATH_MAX];
    size_t index;
    size_t length;

    length = strlen(path);
    if (length == 0 || length >= sizeof(partial)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    memcpy(partial, path, length + 1);
    for (index = 1; index < length; index += 1) {
        if (partial[index] != '/') {
            continue;
        }

        partial[index] = '\0';
        if (mkdir(partial, mode) != 0 && errno != EEXIST) {
            fprintf(stderr, _("failed to create directory: %s\n"), partial);
            return 1;
        }
        partial[index] = '/';
    }

    if (mkdir(partial, mode) != 0 && errno != EEXIST) {
        fprintf(stderr, _("failed to create directory: %s\n"), partial);
        return 1;
    }

    if (stat(path, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, _("not a directory: %s\n"), path);
        return 1;
    }

    return 0;
}

static int secdat_ensure_store_dirs(const char *store_name)
{
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    int status;

    status = secdat_store_entries_dir(store_name, entries_dir, sizeof(entries_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_store_tombstones_dir(store_name, tombstones_dir, sizeof(tombstones_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_ensure_directory(entries_dir, 0700);
    if (status != 0) {
        return status;
    }

    return secdat_ensure_directory(tombstones_dir, 0700);
}

static int secdat_file_exists(const char *path)
{
    struct stat status;

    return stat(path, &status) == 0 && S_ISREG(status.st_mode);
}

static int secdat_remove_if_exists(const char *path)
{
    if (unlink(path) == 0 || errno == ENOENT) {
        return 0;
    }

    fprintf(stderr, _("failed to remove file: %s\n"), path);
    return 1;
}

static int secdat_atomic_write_file(const char *path, const unsigned char *data, size_t length)
{
    char temporary_path[PATH_MAX];
    int file_descriptor;
    size_t offset;
    ssize_t written;
    char *slash;

    slash = strrchr(path, '/');
    if (slash == NULL) {
        fprintf(stderr, _("invalid path: %s\n"), path);
        return 1;
    }

    if ((size_t)(slash - path) + strlen("/.tmp.XXXXXX") + 1 >= sizeof(temporary_path)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    memcpy(temporary_path, path, (size_t)(slash - path));
    temporary_path[slash - path] = '\0';
    strcat(temporary_path, "/.tmp.XXXXXX");

    file_descriptor = mkstemp(temporary_path);
    if (file_descriptor < 0) {
        fprintf(stderr, _("failed to create temporary file for: %s\n"), path);
        return 1;
    }

    if (fchmod(file_descriptor, 0600) != 0) {
        fprintf(stderr, _("failed to set permissions on: %s\n"), temporary_path);
        close(file_descriptor);
        unlink(temporary_path);
        return 1;
    }

    offset = 0;
    while (offset < length) {
        written = write(file_descriptor, data + offset, length - offset);
        if (written <= 0) {
            fprintf(stderr, _("failed to write file: %s\n"), temporary_path);
            close(file_descriptor);
            unlink(temporary_path);
            return 1;
        }
        offset += (size_t)written;
    }

    if (fsync(file_descriptor) != 0) {
        fprintf(stderr, _("failed to fsync file: %s\n"), temporary_path);
        close(file_descriptor);
        unlink(temporary_path);
        return 1;
    }

    if (close(file_descriptor) != 0) {
        fprintf(stderr, _("failed to close file: %s\n"), temporary_path);
        unlink(temporary_path);
        return 1;
    }

    if (rename(temporary_path, path) != 0) {
        fprintf(stderr, _("failed to rename file into place: %s\n"), path);
        unlink(temporary_path);
        return 1;
    }

    return 0;
}

static int secdat_read_file(const char *path, unsigned char **data, size_t *length)
{
    FILE *stream;
    long size;
    unsigned char *buffer;

    stream = fopen(path, "rb");
    if (stream == NULL) {
        fprintf(stderr, _("failed to open file: %s\n"), path);
        return 1;
    }

    if (fseek(stream, 0, SEEK_END) != 0) {
        fclose(stream);
        fprintf(stderr, _("failed to seek file: %s\n"), path);
        return 1;
    }

    size = ftell(stream);
    if (size < 0) {
        fclose(stream);
        fprintf(stderr, _("failed to determine file size: %s\n"), path);
        return 1;
    }

    if (fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        fprintf(stderr, _("failed to seek file: %s\n"), path);
        return 1;
    }

    buffer = malloc((size_t)size);
    if (buffer == NULL && size > 0) {
        fclose(stream);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    if (size > 0 && fread(buffer, 1, (size_t)size, stream) != (size_t)size) {
        fclose(stream);
        free(buffer);
        fprintf(stderr, _("failed to read file: %s\n"), path);
        return 1;
    }

    fclose(stream);
    *data = buffer;
    *length = (size_t)size;
    return 0;
}

static void secdat_write_be32(unsigned char *buffer, uint32_t value)
{
    buffer[0] = (unsigned char)((value >> 24) & 0xff);
    buffer[1] = (unsigned char)((value >> 16) & 0xff);
    buffer[2] = (unsigned char)((value >> 8) & 0xff);
    buffer[3] = (unsigned char)(value & 0xff);
}

static uint32_t secdat_read_be32(const unsigned char *buffer)
{
    return ((uint32_t)buffer[0] << 24)
        | ((uint32_t)buffer[1] << 16)
        | ((uint32_t)buffer[2] << 8)
        | (uint32_t)buffer[3];
}

static int secdat_derive_key(unsigned char key[32])
{
    const char *master_key = getenv("SECDAT_MASTER_KEY");
    unsigned int key_length = 0;

    if (master_key == NULL || master_key[0] == '\0') {
        fprintf(
            stderr,
            _("missing SECDAT_MASTER_KEY; export a secret first, for example: export SECDAT_MASTER_KEY='change-me'\n")
        );
        return 1;
    }

    if (EVP_Digest(master_key, strlen(master_key), key, &key_length, EVP_sha256(), NULL) != 1 || key_length != 32) {
        fprintf(stderr, _("failed to derive encryption key\n"));
        return 1;
    }

    return 0;
}

static int secdat_encrypt_value(const unsigned char *plaintext, size_t plaintext_length, unsigned char **encrypted, size_t *encrypted_length)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char key[32];
    unsigned char nonce[SECDAT_NONCE_LEN];
    unsigned char tag[SECDAT_TAG_LEN];
    unsigned char *buffer = NULL;
    int ciphertext_length;
    int final_length;
    size_t total_ciphertext_length;
    size_t total_length;
    int status = 1;

    if (secdat_derive_key(key) != 0) {
        return 1;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        goto cleanup;
    }

    total_ciphertext_length = plaintext_length + SECDAT_TAG_LEN;
    total_length = SECDAT_HEADER_LEN + sizeof(nonce) + total_ciphertext_length;
    buffer = calloc(1, total_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }

    memcpy(buffer, secdat_entry_magic, sizeof(secdat_entry_magic));
    buffer[8] = SECDAT_ENTRY_VERSION;
    buffer[9] = SECDAT_ENTRY_ALGORITHM_AES_256_GCM;
    buffer[10] = SECDAT_NONCE_LEN;
    buffer[11] = 0;
    secdat_write_be32(buffer + 12, (uint32_t)total_ciphertext_length);
    memcpy(buffer + SECDAT_HEADER_LEN, nonce, sizeof(nonce));

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create encryption context\n"));
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1
        || EVP_EncryptInit_ex(context, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize encryption\n"));
        goto cleanup;
    }

    if (EVP_EncryptUpdate(
            context,
            buffer + SECDAT_HEADER_LEN + sizeof(nonce),
            &ciphertext_length,
            plaintext,
            (int)plaintext_length
        ) != 1) {
        fprintf(stderr, _("failed to encrypt value\n"));
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(context, buffer + SECDAT_HEADER_LEN + sizeof(nonce) + ciphertext_length, &final_length) != 1) {
        fprintf(stderr, _("failed to finalize encryption\n"));
        goto cleanup;
    }

    ciphertext_length += final_length;
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, _("failed to obtain authentication tag\n"));
        goto cleanup;
    }

    memcpy(buffer + SECDAT_HEADER_LEN + sizeof(nonce) + ciphertext_length, tag, sizeof(tag));
    *encrypted = buffer;
    *encrypted_length = total_length;
    buffer = NULL;
    status = 0;

cleanup:
    secdat_secure_clear(key, sizeof(key));
    secdat_secure_clear(tag, sizeof(tag));
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    free(buffer);
    return status;
}

static int secdat_decrypt_value(const unsigned char *encrypted, size_t encrypted_length, unsigned char **plaintext, size_t *plaintext_length)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char key[32];
    unsigned char *buffer = NULL;
    const unsigned char *nonce;
    const unsigned char *ciphertext;
    const unsigned char *tag;
    uint32_t ciphertext_length;
    size_t header_length;
    size_t payload_length;
    size_t decoded_length;
    int written_length;
    int final_length;
    int status = 1;

    if (encrypted_length < SECDAT_HEADER_LEN + SECDAT_NONCE_LEN + SECDAT_TAG_LEN) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }

    if (memcmp(encrypted, secdat_entry_magic, sizeof(secdat_entry_magic)) != 0 || encrypted[8] != SECDAT_ENTRY_VERSION) {
        fprintf(stderr, _("unsupported encrypted entry format\n"));
        return 1;
    }

    if (encrypted[9] != SECDAT_ENTRY_ALGORITHM_AES_256_GCM || encrypted[10] != SECDAT_NONCE_LEN) {
        fprintf(stderr, _("unsupported encryption algorithm\n"));
        return 1;
    }

    ciphertext_length = secdat_read_be32(encrypted + 12);
    header_length = SECDAT_HEADER_LEN + encrypted[10];
    payload_length = encrypted_length - header_length;
    if (payload_length != ciphertext_length || ciphertext_length < SECDAT_TAG_LEN) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }

    if (secdat_derive_key(key) != 0) {
        return 1;
    }

    decoded_length = ciphertext_length - SECDAT_TAG_LEN;
    buffer = malloc(decoded_length == 0 ? 1 : decoded_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }

    nonce = encrypted + SECDAT_HEADER_LEN;
    ciphertext = encrypted + header_length;
    tag = ciphertext + decoded_length;

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create decryption context\n"));
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, encrypted[10], NULL) != 1
        || EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize decryption\n"));
        goto cleanup;
    }

    if (EVP_DecryptUpdate(context, buffer, &written_length, ciphertext, (int)decoded_length) != 1) {
        fprintf(stderr, _("failed to decrypt value\n"));
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, SECDAT_TAG_LEN, (void *)tag) != 1) {
        fprintf(stderr, _("failed to set authentication tag\n"));
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(context, buffer + written_length, &final_length) != 1) {
        fprintf(stderr, _("failed to authenticate encrypted value\n"));
        goto cleanup;
    }

    *plaintext = buffer;
    *plaintext_length = (size_t)(written_length + final_length);
    buffer = NULL;
    status = 0;

cleanup:
    secdat_secure_clear(key, sizeof(key));
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    if (buffer != NULL) {
        secdat_secure_clear(buffer, decoded_length);
        free(buffer);
    }
    return status;
}

static int secdat_read_stdin(unsigned char **buffer, size_t *length)
{
    unsigned char chunk[4096];
    unsigned char *data = NULL;
    size_t used = 0;
    size_t capacity = 0;
    ssize_t read_length;
    unsigned char *new_data;

    while ((read_length = read(STDIN_FILENO, chunk, sizeof(chunk))) > 0) {
        if (used + (size_t)read_length > capacity) {
            capacity = capacity == 0 ? (size_t)read_length : capacity * 2;
            while (capacity < used + (size_t)read_length) {
                capacity *= 2;
            }
            new_data = realloc(data, capacity);
            if (new_data == NULL) {
                secdat_secure_clear(data, used);
                free(data);
                fprintf(stderr, _("out of memory\n"));
                return 1;
            }
            data = new_data;
        }

        memcpy(data + used, chunk, (size_t)read_length);
        used += (size_t)read_length;
    }

    if (read_length < 0) {
        secdat_secure_clear(data, used);
        free(data);
        fprintf(stderr, _("failed to read standard input\n"));
        return 1;
    }

    *buffer = data;
    *length = used;
    return 0;
}

static int secdat_collect_directory_keys(const char *directory_path, const char *suffix, struct secdat_key_list *keys)
{
    DIR *directory;
    struct dirent *entry;
    size_t suffix_length = strlen(suffix);
    size_t name_length;
    char encoded_name[NAME_MAX + 1];
    char *decoded_name = NULL;
    int status = 0;

    directory = opendir(directory_path);
    if (directory == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, _("failed to open directory: %s\n"), directory_path);
        return 1;
    }

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        name_length = strlen(entry->d_name);
        if (name_length <= suffix_length || strcmp(entry->d_name + name_length - suffix_length, suffix) != 0) {
            continue;
        }

        memcpy(encoded_name, entry->d_name, name_length - suffix_length);
        encoded_name[name_length - suffix_length] = '\0';
        if (secdat_unescape_component(encoded_name, &decoded_name) != 0) {
            status = 1;
            break;
        }

        if (secdat_key_list_append(keys, decoded_name) != 0) {
            free(decoded_name);
            status = 1;
            break;
        }

        free(decoded_name);
        decoded_name = NULL;
    }

    closedir(directory);
    return status;
}

static int secdat_collect_visible_keys(const char *store_name, const char *pattern, struct secdat_key_list *visible_keys)
{
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    struct secdat_key_list tombstones = {0};
    struct secdat_key_list entries = {0};
    size_t index;
    int status;

    status = secdat_store_entries_dir(store_name, entries_dir, sizeof(entries_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_store_tombstones_dir(store_name, tombstones_dir, sizeof(tombstones_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_collect_directory_keys(tombstones_dir, ".tomb", &tombstones);
    if (status != 0) {
        goto cleanup;
    }

    status = secdat_collect_directory_keys(entries_dir, ".sec", &entries);
    if (status != 0) {
        goto cleanup;
    }

    for (index = 0; index < entries.count; index += 1) {
        if (secdat_key_list_contains(&tombstones, entries.items[index])) {
            continue;
        }
        if (pattern != NULL && fnmatch(pattern, entries.items[index], 0) != 0) {
            continue;
        }
        if (secdat_key_list_append(visible_keys, entries.items[index]) != 0) {
            status = 1;
            goto cleanup;
        }
    }

    qsort(visible_keys->items, visible_keys->count, sizeof(*visible_keys->items), secdat_compare_strings);

cleanup:
    secdat_key_list_free(&entries);
    secdat_key_list_free(&tombstones);
    return status;
}

static int secdat_command_ls(const struct secdat_cli *cli)
{
    struct secdat_key_list visible_keys = {0};
    const char *pattern = NULL;
    size_t index;

    if (cli->argc == 2 && strcmp(cli->argv[0], "--pattern") == 0) {
        pattern = cli->argv[1];
    } else if (cli->argc != 0) {
        fprintf(stderr, _("invalid arguments for ls\n"));
        return 2;
    }

    if (secdat_collect_visible_keys(cli->store, pattern, &visible_keys) != 0) {
        secdat_key_list_free(&visible_keys);
        return 1;
    }

    for (index = 0; index < visible_keys.count; index += 1) {
        puts(visible_keys.items[index]);
    }

    secdat_key_list_free(&visible_keys);
    return 0;
}

static int secdat_command_get(const struct secdat_cli *cli)
{
    char entry_path[PATH_MAX];
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    ssize_t written;
    size_t offset;

    if (cli->argc != 1 && !(cli->argc == 2 && strcmp(cli->argv[1], "--stdout") == 0)) {
        fprintf(stderr, _("invalid arguments for get\n"));
        return 2;
    }

    if (isatty(STDOUT_FILENO)) {
        fprintf(stderr, _("refusing to write secret to a terminal\n"));
        return 1;
    }

    if (secdat_build_entry_path(cli->store, cli->argv[0], entry_path, sizeof(entry_path)) != 0) {
        return 1;
    }

    if (!secdat_file_exists(entry_path)) {
        fprintf(stderr, _("key not found: %s\n"), cli->argv[0]);
        return 1;
    }

    if (secdat_read_file(entry_path, &encrypted, &encrypted_length) != 0) {
        return 1;
    }

    if (secdat_decrypt_value(encrypted, encrypted_length, &plaintext, &plaintext_length) != 0) {
        free(encrypted);
        return 1;
    }

    offset = 0;
    while (offset < plaintext_length) {
        written = write(STDOUT_FILENO, plaintext + offset, plaintext_length - offset);
        if (written <= 0) {
            fprintf(stderr, _("failed to write standard output\n"));
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            free(encrypted);
            return 1;
        }
        offset += (size_t)written;
    }

    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    free(encrypted);
    return 0;
}

static int secdat_store_plaintext(const struct secdat_cli *cli, const char *key, unsigned char *plaintext, size_t plaintext_length)
{
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    int status;

    status = secdat_ensure_store_dirs(cli->store);
    if (status != 0) {
        return status;
    }

    status = secdat_build_entry_path(cli->store, key, entry_path, sizeof(entry_path));
    if (status != 0) {
        return status;
    }

    status = secdat_build_tombstone_path(cli->store, key, tombstone_path, sizeof(tombstone_path));
    if (status != 0) {
        return status;
    }

    if (secdat_encrypt_value(plaintext, plaintext_length, &encrypted, &encrypted_length) != 0) {
        return 1;
    }

    status = secdat_remove_if_exists(tombstone_path);
    if (status == 0) {
        status = secdat_atomic_write_file(entry_path, encrypted, encrypted_length);
    }

    secdat_secure_clear(encrypted, encrypted_length);
    free(encrypted);
    return status;
}

static int secdat_command_set(const struct secdat_cli *cli)
{
    const char *key;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    const char *environment_name;
    const char *environment_value;
    int status;

    if (cli->argc < 1) {
        fprintf(stderr, _("missing key for set\n"));
        return 2;
    }

    key = cli->argv[0];
    if (cli->argc == 1 || (cli->argc == 2 && strcmp(cli->argv[1], "--stdin") == 0)) {
        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, _("refusing to read secret from a terminal\n"));
            return 1;
        }

        if (secdat_read_stdin(&plaintext, &plaintext_length) != 0) {
            return 1;
        }
    } else if (cli->argc == 2 && cli->argv[1][0] != '-') {
        plaintext_length = strlen(cli->argv[1]);
        plaintext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
        if (plaintext == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        memcpy(plaintext, cli->argv[1], plaintext_length);
    } else if (cli->argc == 3 && strcmp(cli->argv[1], "--value") == 0) {
        plaintext_length = strlen(cli->argv[2]);
        plaintext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
        if (plaintext == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        memcpy(plaintext, cli->argv[2], plaintext_length);
    } else if (cli->argc == 3 && strcmp(cli->argv[1], "--env") == 0) {
        environment_name = cli->argv[2];
        environment_value = getenv(environment_name);
        if (environment_value == NULL) {
            fprintf(stderr, _("environment variable is not set: %s\n"), environment_name);
            return 1;
        }

        plaintext_length = strlen(environment_value);
        plaintext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
        if (plaintext == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        memcpy(plaintext, environment_value, plaintext_length);
    } else {
        fprintf(stderr, _("invalid arguments for set\n"));
        return 2;
    }

    status = secdat_store_plaintext(cli, key, plaintext, plaintext_length);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    return status;
}

static int secdat_command_rm(const struct secdat_cli *cli)
{
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];

    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for rm\n"));
        return 2;
    }

    if (secdat_build_entry_path(cli->store, cli->argv[0], entry_path, sizeof(entry_path)) != 0) {
        return 1;
    }
    if (secdat_build_tombstone_path(cli->store, cli->argv[0], tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }

    if (!secdat_file_exists(entry_path)) {
        fprintf(stderr, _("key not found: %s\n"), cli->argv[0]);
        return 1;
    }

    if (unlink(entry_path) != 0) {
        fprintf(stderr, _("failed to remove key: %s\n"), cli->argv[0]);
        return 1;
    }

    return secdat_remove_if_exists(tombstone_path);
}

int secdat_run_command(const struct secdat_cli *cli)
{
    switch (cli->command) {
    case SECDAT_COMMAND_LS:
        return secdat_command_ls(cli);
    case SECDAT_COMMAND_GET:
        return secdat_command_get(cli);
    case SECDAT_COMMAND_SET:
        return secdat_command_set(cli);
    case SECDAT_COMMAND_RM:
        return secdat_command_rm(cli);
    default:
        fprintf(stderr, _("command not implemented yet: %s\n"), secdat_cli_command_name(cli->command));
        if (cli->dir != NULL) {
            fprintf(stderr, _("  dir=%s\n"), cli->dir);
        }
        if (cli->store != NULL) {
            fprintf(stderr, _("  store=%s\n"), cli->store);
        }
        return 1;
    }
}