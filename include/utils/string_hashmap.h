#ifndef STRING_HASHMAP_H
#define STRING_HASHMAP_H

#include <stdlib.h>

struct string_hashmap_t{
    struct node** arr_map;
    size_t size;
    size_t capacity;
};

enum hashmap_error {
    HASHMAP_SUCCESS = 0,
    HASHMAP_ERROR_NO_MEMORY = -1,
    HASHMAP_ERROR_KEY_NOT_FOUND = -2,
    HASHMAP_ERROR_INVALID_ARG = -3,
    HASHMAP_ERROR_STOP_ITERATION = -4
};

// Creation and destruction
struct string_hashmap_t* string_hashmap_t_create(void);
enum hashmap_error string_hashmap_free(struct string_hashmap_t* hashmap);

// Basic operations
enum hashmap_error string_hashmap_put(struct string_hashmap_t* hashmap, const char* key, const char* value, size_t key_len, size_t value_len);
enum hashmap_error string_hashmap_get(const struct string_hashmap_t* hashmap, const char* key, size_t key_len, char** return_value);
enum hashmap_error string_hashmap_remove(struct string_hashmap_t* hashmap, const char* key, size_t key_len);
enum hashmap_error string_hashmap_contains(const struct string_hashmap_t* hashmap, const char* key, size_t key_len, int* return_contains);

// Utility operations
enum hashmap_error string_hashmap_clear(struct string_hashmap_t* hashmap);
enum hashmap_error string_hashmap_size(const struct string_hashmap_t* hashmap, size_t* return_size);
enum hashmap_error string_hashmap_is_empty(const struct string_hashmap_t* hashmap, int* return_is_empty);
enum hashmap_error string_hashmap_capacity(const struct string_hashmap_t* hashmap, size_t* return_capacity);

// Case-insensitive helpers (keys compared case-insensitively)
enum hashmap_error string_hashmap_put_case_insensitive(struct string_hashmap_t* hashmap, const char* key, const char* value, size_t key_len, size_t value_len);
enum hashmap_error string_hashmap_get_case_insensitive(const struct string_hashmap_t* hashmap, const char* key, size_t key_len, char** return_value);

// Iterator callback
typedef int (*string_hashmap_foreach_cb)(const char* key, size_t key_len, const char* value, size_t value_len, void* user_data);

enum hashmap_error string_hashmap_foreach(const struct string_hashmap_t* hashmap, string_hashmap_foreach_cb callback, void* user_data);

#endif