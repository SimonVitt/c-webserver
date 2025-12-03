/**
 * @file string_builder.h
 * @brief Dynamic string buffer for efficient concatenation
 */

#ifndef STRING_BUILDER_H
#define STRING_BUILDER_H

#include <stddef.h>
#include <stdarg.h>

/** @brief Dynamic string buffer */
struct string_builder_t {
    char* data;
    size_t length;
    size_t capacity;
};

/** @brief Operation result codes */
enum string_builder_error {
    STRING_BUILDER_SUCCESS = 0,
    STRING_BUILDER_ERROR_NO_MEMORY = -1,
    STRING_BUILDER_ERROR_INVALID_INPUT = -2,
    STRING_BUILDER_ERROR_OUT_OF_BOUNDS = -3
};

/**
 * @brief Create string builder with default capacity
 * @return New builder or NULL on allocation failure
 */
struct string_builder_t* string_builder_t_create(void);

/**
 * @brief Create string builder with specified capacity
 */
struct string_builder_t* string_builder_t_create_with_capacity(size_t initial_capacity);

/**
 * @brief Free string builder
 */
enum string_builder_error string_builder_free(struct string_builder_t* sb);

/** @brief Append single character */
enum string_builder_error string_builder_append_char(struct string_builder_t* sb, char c);

/** @brief Append null-terminated string */
enum string_builder_error string_builder_append_string(struct string_builder_t* sb, const char* str);

/**
 * @brief Append n bytes (not null-terminated)
 * @note Safe to call with n=0
 */
enum string_builder_error string_builder_append_string_n(struct string_builder_t* sb, 
    const char* str, size_t n);

/** @brief Append integer as decimal string */
enum string_builder_error string_builder_append_int(struct string_builder_t* sb, int value);

/** @brief Append long as decimal string */
enum string_builder_error string_builder_append_long(struct string_builder_t* sb, long value);

/** @brief Append size_t as decimal string */
enum string_builder_error string_builder_append_size_t(struct string_builder_t* sb, size_t value);

/** @brief Append printf-style formatted string */
enum string_builder_error string_builder_append_format(struct string_builder_t* sb, 
    const char* format, ...);

/** @brief Append vprintf-style formatted string */
enum string_builder_error string_builder_append_vformat(struct string_builder_t* sb, 
    const char* format, va_list args);

/** @brief Insert character at position */
enum string_builder_error string_builder_insert_char(struct string_builder_t* sb, 
    size_t pos, char c);

/** @brief Insert null-terminated string at position */
enum string_builder_error string_builder_insert_string(struct string_builder_t* sb, 
    size_t pos, const char* str);

/** @brief Insert n bytes at position */
enum string_builder_error string_builder_insert_string_n(struct string_builder_t* sb, 
    size_t pos, const char* str, size_t n);

/** @brief Remove length bytes starting at pos */
enum string_builder_error string_builder_remove(struct string_builder_t* sb, 
    size_t pos, size_t length);

/** @brief Clear contents (keeps capacity) */
enum string_builder_error string_builder_clear(struct string_builder_t* sb);

/** @brief Get character at position */
enum string_builder_error string_builder_get_char(const struct string_builder_t* sb, 
    size_t pos, char* out_char);

/** @brief Set character at position */
enum string_builder_error string_builder_set_char(struct string_builder_t* sb, 
    size_t pos, char c);

/**
 * @brief Create copy of string contents
 * @param out_string  Output: newly allocated string (caller must free)
 */
enum string_builder_error string_builder_to_string(const struct string_builder_t* sb, 
    char** out_string);

/**
 * @brief Get internal buffer (no copy)
 * @return Null-terminated string, valid until next mutation
 */
const char* string_builder_c_str(const struct string_builder_t* sb);

/** @brief Get current length */
enum string_builder_error string_builder_length(const struct string_builder_t* sb, 
    size_t* out_length);

/** @brief Get current capacity */
enum string_builder_error string_builder_capacity(const struct string_builder_t* sb, 
    size_t* out_capacity);

/** @brief Check if empty */
enum string_builder_error string_builder_is_empty(const struct string_builder_t* sb, 
    int* out_is_empty);

/** @brief Pre-allocate capacity */
enum string_builder_error string_builder_reserve(struct string_builder_t* sb, 
    size_t new_capacity);

#endif
