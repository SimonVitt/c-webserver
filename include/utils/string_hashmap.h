/**
 * @file string_hashmap.h
 * @brief String-to-string hash map with case-insensitive option
 */

#ifndef STRING_HASHMAP_H
#define STRING_HASHMAP_H

#include <stdlib.h>

/** @brief Hash map instance */
struct string_hashmap_t {
    struct node** arr_map;
    size_t size;
    size_t capacity;
};

/** @brief Operation result codes */
enum hashmap_error {
    HASHMAP_SUCCESS = 0,
    HASHMAP_ERROR_NO_MEMORY = -1,
    HASHMAP_ERROR_KEY_NOT_FOUND = -2,
    HASHMAP_ERROR_INVALID_ARG = -3,
    HASHMAP_ERROR_STOP_ITERATION = -4
};

/**
 * @brief Create empty hash map
 * @return New hash map or NULL on allocation failure
 */
struct string_hashmap_t* string_hashmap_t_create(void);

/**
 * @brief Free hash map and all entries
 */
enum hashmap_error string_hashmap_free(struct string_hashmap_t* hashmap);

/**
 * @brief Insert or update key-value pair
 * @param key_len    Key length (not including null terminator)
 * @param value_len  Value length (not including null terminator)
 */
enum hashmap_error string_hashmap_put(struct string_hashmap_t* hashmap, 
    const char* key, const char* value, size_t key_len, size_t value_len);

/**
 * @brief Get value by key
 * @param return_value  Output: pointer to internal value (do not free)
 * @return HASHMAP_ERROR_KEY_NOT_FOUND if not present
 */
enum hashmap_error string_hashmap_get(const struct string_hashmap_t* hashmap, 
    const char* key, size_t key_len, char** return_value);

/** @brief Remove entry by key */
enum hashmap_error string_hashmap_remove(struct string_hashmap_t* hashmap, 
    const char* key, size_t key_len);

/** @brief Check if key exists */
enum hashmap_error string_hashmap_contains(const struct string_hashmap_t* hashmap, 
    const char* key, size_t key_len, int* return_contains);

/** @brief Remove all entries */
enum hashmap_error string_hashmap_clear(struct string_hashmap_t* hashmap);

/** @brief Get entry count */
enum hashmap_error string_hashmap_size(const struct string_hashmap_t* hashmap, 
    size_t* return_size);

/** @brief Check if empty */
enum hashmap_error string_hashmap_is_empty(const struct string_hashmap_t* hashmap, 
    int* return_is_empty);

/** @brief Get bucket count */
enum hashmap_error string_hashmap_capacity(const struct string_hashmap_t* hashmap, 
    size_t* return_capacity);

/** @brief Put with case-insensitive key (for HTTP headers) */
enum hashmap_error string_hashmap_put_case_insensitive(struct string_hashmap_t* hashmap, 
    const char* key, const char* value, size_t key_len, size_t value_len);

/** @brief Get with case-insensitive key lookup */
enum hashmap_error string_hashmap_get_case_insensitive(const struct string_hashmap_t* hashmap, 
    const char* key, size_t key_len, char** return_value);

/**
 * @brief Iterator callback type
 * @return 0 to continue, non-zero to stop iteration
 */
typedef int (*string_hashmap_foreach_cb)(const char* key, size_t key_len, 
    const char* value, size_t value_len, void* user_data);

/** @brief Iterate all entries */
enum hashmap_error string_hashmap_foreach(const struct string_hashmap_t* hashmap, 
    string_hashmap_foreach_cb callback, void* user_data);

#endif
