#ifndef STRING_BUILDER_H
#define STRING_BUILDER_H

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>

struct string_builder_t{
    char* data;
    size_t length;
    size_t capacity;
};

enum string_builder_error {
    STRING_BUILDER_SUCCESS = 0,
    STRING_BUILDER_ERROR_NO_MEMORY = -1,
    STRING_BUILDER_ERROR_INVALID_INPUT = -2,
    STRING_BUILDER_ERROR_OUT_OF_BOUNDS = -3
};

// Opaque type - internal details hidden from users
struct string_builder_t;

// Core lifecycle functions
struct string_builder_t* string_builder_t_create(void);
struct string_builder_t* string_builder_t_create_with_capacity(size_t initial_capacity);
enum string_builder_error string_builder_free(struct string_builder_t* sb);

// Basic string operations
enum string_builder_error string_builder_append_char(struct string_builder_t* sb, char c);
enum string_builder_error string_builder_append_string(struct string_builder_t* sb, const char* str);
enum string_builder_error string_builder_append_string_n(struct string_builder_t* sb, const char* str, size_t n);
enum string_builder_error string_builder_append_int(struct string_builder_t* sb, int value);
enum string_builder_error string_builder_append_long(struct string_builder_t* sb, long value);
enum string_builder_error string_builder_append_size_t(struct string_builder_t* sb, size_t value);

// Formatted string operations (essential for HTTP responses)
enum string_builder_error string_builder_append_format(struct string_builder_t* sb, const char* format, ...);
enum string_builder_error string_builder_append_vformat(struct string_builder_t* sb, const char* format, va_list args);

// Insert operations
enum string_builder_error string_builder_insert_char(struct string_builder_t* sb, size_t pos, char c);
enum string_builder_error string_builder_insert_string(struct string_builder_t* sb, size_t pos, const char* str);
enum string_builder_error string_builder_insert_string_n(struct string_builder_t* sb, size_t pos, const char* str, size_t n);

// Remove operations
enum string_builder_error string_builder_remove(struct string_builder_t* sb, size_t pos, size_t length);
enum string_builder_error string_builder_clear(struct string_builder_t* sb);

// Access operations
enum string_builder_error string_builder_get_char(const struct string_builder_t* sb, size_t pos, char* out_char);
enum string_builder_error string_builder_set_char(struct string_builder_t* sb, size_t pos, char c);
enum string_builder_error string_builder_to_string(const struct string_builder_t* sb, char** out_string);
const char* string_builder_c_str(const struct string_builder_t* sb);

// Utility functions
enum string_builder_error string_builder_length(const struct string_builder_t* sb, size_t* out_length);
enum string_builder_error string_builder_capacity(const struct string_builder_t* sb, size_t* out_capacity);
enum string_builder_error string_builder_is_empty(const struct string_builder_t* sb, int* out_is_empty);
enum string_builder_error string_builder_reserve(struct string_builder_t* sb, size_t new_capacity);

#endif