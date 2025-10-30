#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "./../include/utils/string_builder.h"

#define DEFAULT_STRING_BUILDER_STRING_CAPACITY 4096
#define STRING_BUILDER_GROWTH_FACTOR 2

struct string_builder_t* string_builder_t_create(void){

    struct string_builder_t* sb = malloc(sizeof(struct string_builder_t));
    if (!sb) return NULL;
    
    sb->data = malloc(DEFAULT_STRING_BUILDER_STRING_CAPACITY * sizeof(char));
    if (!sb->data) {
        free(sb);
        return NULL;
    }
    
    sb->data[0] = '\0';
    sb->capacity = DEFAULT_STRING_BUILDER_STRING_CAPACITY;
    sb->length = 0;
    return sb;
}

struct string_builder_t* string_builder_t_create_with_capacity(size_t capacity){
    struct string_builder_t* sb = malloc(sizeof(struct string_builder_t));
    if (!sb) return NULL;
    
    sb->data = malloc(capacity * sizeof(char));
    if (!sb->data) {
        free(sb);
        return NULL;
    }
    
    sb->data[0] = '\0';
    sb->capacity = capacity;
    sb->length = 0;
    return sb;
}

enum string_builder_error string_builder_free(struct string_builder_t* sb){
    if (!sb) return STRING_BUILDER_SUCCESS;
    free(sb->data);
    free(sb);
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_resize(struct string_builder_t* sb, size_t new_capacity){
    char* new_data = realloc(sb->data, new_capacity);
    if (!new_data){
        return STRING_BUILDER_ERROR_NO_MEMORY;
    }
    sb->data = new_data;
    sb->capacity = new_capacity;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_ensure_capacity(struct string_builder_t* sb, size_t n){
    if (SIZE_MAX - sb->length < n + 1) {
        return STRING_BUILDER_ERROR_NO_MEMORY;
    }
    size_t needed_capacity = sb->length + n + 1;
    if (needed_capacity > sb->capacity) {
        size_t new_capacity;
        if (SIZE_MAX / STRING_BUILDER_GROWTH_FACTOR >= sb->capacity) {
            new_capacity = sb->capacity * STRING_BUILDER_GROWTH_FACTOR;
        } else{
            new_capacity = needed_capacity;
        }

        if (new_capacity < needed_capacity) {
            new_capacity = needed_capacity;
        }
        return string_builder_resize(sb, new_capacity);
    }
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_append_char(struct string_builder_t* sb, char c){
    if (sb->length == sb->capacity - 1){
        if (SIZE_MAX / STRING_BUILDER_GROWTH_FACTOR < sb->capacity){
            return STRING_BUILDER_ERROR_NO_MEMORY;
        }
        enum string_builder_error resize_success = string_builder_resize(sb, sb->capacity * STRING_BUILDER_GROWTH_FACTOR);
        if (resize_success != STRING_BUILDER_SUCCESS){
            return resize_success;
        }
    }
    sb->data[sb->length] = c;
    sb->length++;
    sb->data[sb->length] = '\0';
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_append_string(struct string_builder_t* sb, const char* str){
    size_t new_length = sb->length;
    while (*str != '\0'){
        if (new_length == sb->capacity - 1){
            if (SIZE_MAX / STRING_BUILDER_GROWTH_FACTOR < sb->capacity){
                sb->data[sb->length] = '\0';
                return STRING_BUILDER_ERROR_NO_MEMORY;
            }
            enum string_builder_error resize_success = string_builder_resize(sb, sb->capacity * STRING_BUILDER_GROWTH_FACTOR);
            if (resize_success != STRING_BUILDER_SUCCESS){
                sb->data[sb->length] = '\0';
                return resize_success;
            }
        }
        sb->data[new_length] = *str;
        new_length++;
        str++;
    }
    sb->length = new_length;
    sb->data[sb->length] = '\0';
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_append_string_n(struct string_builder_t* sb, const char* str, size_t n){
    enum string_builder_error ensure_cap_res = string_builder_ensure_capacity(sb, n);
    if (ensure_cap_res != STRING_BUILDER_SUCCESS){
        return ensure_cap_res;
    }
    memcpy(sb->data + sb->length, str, n);
    sb->length = sb->length + n;
    sb->data[sb->length] = '\0';
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_append_int(struct string_builder_t* sb, int value){
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "%d", value);
    return string_builder_append_string_n(sb, buffer, len);
}

enum string_builder_error string_builder_append_long(struct string_builder_t* sb, long value){
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "%ld", value);
    return string_builder_append_string_n(sb, buffer, len);
}

enum string_builder_error string_builder_append_size_t(struct string_builder_t* sb, size_t value){
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "%zu", value);
    return string_builder_append_string_n(sb, buffer, len);
}

enum string_builder_error string_builder_append_float(struct string_builder_t* sb, float value){
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "%.6g", value);
    return string_builder_append_string_n(sb, buffer, len);
}

enum string_builder_error string_builder_append_double(struct string_builder_t* sb, double value){
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "%.6g", value);
    return string_builder_append_string_n(sb, buffer, len);
}

enum string_builder_error string_builder_append_vformat(struct string_builder_t* sb, const char* format, va_list args){
    char buffer[4096];
    int len = vsnprintf(buffer, sizeof(buffer), format, args);
    if (len < 0) {
        return STRING_BUILDER_ERROR_INVALID_INPUT;
    }
    if (len >= (int)sizeof(buffer)) {
        char* dynamic_buffer = malloc(len + 1);
        if (!dynamic_buffer) {
            return STRING_BUILDER_ERROR_NO_MEMORY;
        }
        
        va_list args_copy;
        va_copy(args_copy, args);
        vsnprintf(dynamic_buffer, len + 1, format, args_copy);
        va_end(args_copy);
        
        enum string_builder_error result = string_builder_append_string_n(sb, dynamic_buffer, len);
        free(dynamic_buffer);
        return result;
    }
    return string_builder_append_string_n(sb, buffer, len);
}

enum string_builder_error string_builder_append_format(struct string_builder_t* sb, const char* format, ...){
    va_list args;
    va_start(args, format);

    enum string_builder_error result = string_builder_append_vformat(sb, format, args);

    va_end(args);
    return result;
}

enum string_builder_error string_builder_insert_char(struct string_builder_t* sb, size_t pos, char c){
    if (pos > sb->length){
        return STRING_BUILDER_ERROR_OUT_OF_BOUNDS;
    }
    enum string_builder_error ensure_cap_res = string_builder_ensure_capacity(sb, 1);
    if (ensure_cap_res != STRING_BUILDER_SUCCESS){
        return ensure_cap_res;
    }

    for (size_t i = sb->length + 1; i > pos; i--){
        sb->data[i] = sb->data[i - 1];
    }
    sb->data[pos] = c;
    sb->length++;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_insert_string_n(struct string_builder_t* sb, size_t pos, const char* str, size_t n){
    if (pos > sb->length){
        return STRING_BUILDER_ERROR_OUT_OF_BOUNDS;
    }
    enum string_builder_error ensure_cap_res = string_builder_ensure_capacity(sb, n);
    if (ensure_cap_res != STRING_BUILDER_SUCCESS){
        return ensure_cap_res;
    }

    for (size_t i = sb->length + n; i >= pos + n; i--){
        sb->data[i] = sb->data[i - n];
    }

    for (size_t i = 0; i < n; i++){
        sb->data[pos + i] = *str;
        str++;
    }

    sb->length = sb->length + n;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_insert_string(struct string_builder_t* sb, size_t pos, const char* str){
    size_t len = strlen(str);
    return string_builder_insert_string_n(sb, pos, str, len);
}

enum string_builder_error string_builder_remove(struct string_builder_t* sb, size_t pos, size_t length){
    if (pos > sb->length){
        return STRING_BUILDER_ERROR_OUT_OF_BOUNDS;
    }
    if (length > sb->length - pos){
        return STRING_BUILDER_ERROR_OUT_OF_BOUNDS;
    }
    size_t i = pos + length;
    while (i <= sb->length){
        sb->data[i - length] = sb->data[i];
        i++;
    }
    sb->length -= length;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_clear(struct string_builder_t* sb){
    sb->data[0] = '\0';
    sb->length = 0;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_get_char(const struct string_builder_t* sb, size_t pos, char* out_char){
    if (pos >= sb->length){
        return STRING_BUILDER_ERROR_OUT_OF_BOUNDS;
    }
    *out_char = sb->data[pos];
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_set_char(struct string_builder_t* sb, size_t pos, char c){
    if (pos >= sb->length){
        return STRING_BUILDER_ERROR_OUT_OF_BOUNDS;
    }
    sb->data[pos] = c;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_to_string(const struct string_builder_t* sb, char** out_string){
    *out_string = malloc((sb->length + 1) * sizeof(char));
    if (!*out_string){
        return STRING_BUILDER_ERROR_NO_MEMORY;
    }
    
    memcpy(*out_string, sb->data, sb->length + 1);
    return STRING_BUILDER_SUCCESS;
}

const char* string_builder_c_str(const struct string_builder_t* sb){
    return sb->data;
}

enum string_builder_error string_builder_length(const struct string_builder_t* sb, size_t* out_length){
    *out_length = sb->length;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_capacity(const struct string_builder_t* sb, size_t* out_capacity){
    *out_capacity = sb->capacity;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_is_empty(const struct string_builder_t* sb, int* out_is_empty){
    *out_is_empty = sb->length == 0;
    return STRING_BUILDER_SUCCESS;
}

enum string_builder_error string_builder_reserve(struct string_builder_t* sb, size_t new_capacity){
    if (new_capacity >= SIZE_MAX) {
        return STRING_BUILDER_ERROR_NO_MEMORY;
    }
    if (new_capacity + 1 <= sb->capacity){
        return STRING_BUILDER_SUCCESS;
    }

    return string_builder_resize(sb, new_capacity + 1);
}