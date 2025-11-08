#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "./../include/utils/string_hashmap.h"

#define HASHMAP_INITIAL_CAPACITY 16
#define HASHMAP_GROWTH_FACTOR 2
#define HASHMAP_LOAD_FACTOR_NUMERATOR 3
#define HASHMAP_LOAD_FACTOR_DENOMINATOR 4
#define HASHMAP_HASH_MULTIPLIER 2654435761u 

struct node{
    struct node* next;
    char* value;
    char* key;
    size_t key_len;
    size_t value_len;
};

struct string_hashmap_t* string_hashmap_t_create(void){
    struct string_hashmap_t* hashmap = malloc(sizeof(struct string_hashmap_t));
    if (!hashmap) return NULL;

    hashmap->arr_map = calloc(HASHMAP_INITIAL_CAPACITY, sizeof(struct node*));
    if (!hashmap->arr_map){
        free(hashmap);
        return NULL;
    }
    hashmap->size = 0;
    hashmap->capacity = HASHMAP_INITIAL_CAPACITY;
    return hashmap;
}

enum hashmap_error string_hashmap_free_nodes(struct node** arr_map, size_t capacity){
    for (size_t i = 0; i < capacity; i++){
        struct node* curr = arr_map[i];
        struct node* prev = NULL;
        while (curr != NULL){
            prev = curr;
            curr = curr->next;
            free(prev->key);
            free(prev->value);
            free(prev);
        }
    }
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_free(struct string_hashmap_t* hashmap){
    string_hashmap_free_nodes(hashmap->arr_map, hashmap->capacity);
    free(hashmap->arr_map);
    free(hashmap);
    return HASHMAP_SUCCESS;
}

size_t string_hashmap_get_hash_index(size_t capacity, const char* key, size_t key_len){
    size_t hash = 0;
    for (size_t i = 0; i < key_len; i++){
        hash = hash * HASHMAP_HASH_MULTIPLIER + (size_t)key[i]; //  rolling hash, so that for example abc and cba have different hashes
    }
    return hash & (capacity - 1);
}

enum hashmap_error string_hashmap_insert_in_array(struct node** arr, size_t index, const char* key, const char* value, size_t key_len, size_t value_len, int* was_inserted){
    struct node* curr = arr[index];
    struct node* prev = NULL;
    while (curr != NULL){
        if (key_len == curr->key_len && !memcmp(curr->key, key, key_len)){
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    if (curr != NULL){
        char* new_arr = realloc(curr->value, sizeof(char) * (value_len + 1));
        if (!new_arr) return HASHMAP_ERROR_NO_MEMORY;
        curr->value = new_arr;
        memcpy(curr->value, value, value_len);
        curr->value_len = value_len;
        curr->value[value_len] = '\0';
        *was_inserted = 0;  // Was an update
        return HASHMAP_SUCCESS;
    }

    struct node* new_node = malloc(sizeof(struct node));
    if (!new_node) return HASHMAP_ERROR_NO_MEMORY;

    new_node->value = malloc(sizeof(char) * (value_len + 1));
    if (!new_node->value){
        free(new_node);
        return HASHMAP_ERROR_NO_MEMORY;
    }
    memcpy(new_node->value, value, value_len);
    new_node->value[value_len] = '\0';
    new_node->value_len = value_len;

    new_node->key = malloc(sizeof(char) * (key_len + 1));
    if (!new_node->key){
        free(new_node->value);
        free(new_node);
        return HASHMAP_ERROR_NO_MEMORY;
    }
    memcpy(new_node->key, key, key_len);
    new_node->key[key_len] = '\0';
    new_node->key_len = key_len;

    new_node->next = NULL;

    if (prev != NULL){
        prev->next = new_node;
    }else{
        arr[index] = new_node;
    }
    *was_inserted = 1;  // Was an insert
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_rehash(struct string_hashmap_t* hashmap){
    // Check for overflow before multiplying capacity
    if (hashmap->capacity > SIZE_MAX / HASHMAP_GROWTH_FACTOR) {
        return HASHMAP_ERROR_NO_MEMORY;
    }
    
    struct node** new_arr = calloc(hashmap->capacity * HASHMAP_GROWTH_FACTOR, sizeof(struct node*));
    if (new_arr == NULL){
        return HASHMAP_ERROR_NO_MEMORY;
    }
    for (size_t i = 0; i < hashmap->capacity; i++){
        struct node* curr = hashmap->arr_map[i];
        while (curr != NULL){
            struct node* next = curr->next;
            size_t index = string_hashmap_get_hash_index(hashmap->capacity * HASHMAP_GROWTH_FACTOR, curr->key, curr->key_len);
            
            curr->next = new_arr[index];
            new_arr[index] = curr;

            curr = next;
        }
    }
    // Only free the array, NOT the nodes (they're now in new_arr)
    free(hashmap->arr_map);
    hashmap->capacity = hashmap->capacity * HASHMAP_GROWTH_FACTOR;
    hashmap->arr_map = new_arr;
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_put(struct string_hashmap_t* hashmap, const char* key, const char* value, size_t key_len, size_t value_len){
    if (hashmap->size * HASHMAP_LOAD_FACTOR_DENOMINATOR >= hashmap->capacity * HASHMAP_LOAD_FACTOR_NUMERATOR){
        enum hashmap_error rehash_result = string_hashmap_rehash(hashmap);
        if (rehash_result != HASHMAP_SUCCESS){
            return rehash_result;
        }
    }
    size_t index = string_hashmap_get_hash_index(hashmap->capacity, key, key_len);
    int was_inserted;
    enum hashmap_error insert_result = string_hashmap_insert_in_array(hashmap->arr_map, index, key, value, key_len, value_len, &was_inserted);
    if (insert_result == HASHMAP_SUCCESS && was_inserted) {
        hashmap->size++;
    }
    return insert_result;
}

enum hashmap_error string_hashmap_remove(struct string_hashmap_t* hashmap, const char* key, size_t key_len){
    size_t index = string_hashmap_get_hash_index(hashmap->capacity, key, key_len);
    struct node* curr = hashmap->arr_map[index];
    struct node* prev = NULL;
    while (curr != NULL && (key_len != curr->key_len || memcmp(curr->key, key, key_len))){
        prev = curr;
        curr = curr->next;
    }
    if (curr != NULL){
        if (prev){
            prev->next = curr->next;
        } else {
            hashmap->arr_map[index] = curr->next;
        }
        free(curr->key);
        free(curr->value);
        free(curr);
        hashmap->size--;
    }
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_get(const struct string_hashmap_t* hashmap, const char* key, size_t key_len, char** return_value){
    size_t index = string_hashmap_get_hash_index(hashmap->capacity, key, key_len);
    struct node* curr = hashmap->arr_map[index];
    while (curr != NULL && (key_len != curr->key_len || memcmp(curr->key, key, key_len))){
        curr = curr->next;
    }
    if (curr != NULL){
        *return_value = curr->value;
    }else{
        return HASHMAP_ERROR_KEY_NOT_FOUND;
    }
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_contains(const struct string_hashmap_t* hashmap, const char* key, size_t key_len, int* return_contains){
    size_t index = string_hashmap_get_hash_index(hashmap->capacity, key, key_len);
    struct node* curr = hashmap->arr_map[index];
    while (curr != NULL && (key_len != curr->key_len || memcmp(curr->key, key, key_len))){
        curr = curr->next;
    }
    if (curr != NULL){
        *return_contains = 1;
    }else{
        *return_contains = 0;
    }
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_clear(struct string_hashmap_t* hashmap){
    string_hashmap_free_nodes(hashmap->arr_map, hashmap->capacity);
    memset(hashmap->arr_map, 0, hashmap->capacity * sizeof(struct node*));
    hashmap->size = 0;
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_size(const struct string_hashmap_t* hashmap, size_t* return_size){
    *return_size = hashmap->size;
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_is_empty(const struct string_hashmap_t* hashmap, int* return_is_empty){
    *return_is_empty = hashmap->size == 0;
    return HASHMAP_SUCCESS;
}

enum hashmap_error string_hashmap_capacity(const struct string_hashmap_t* hashmap, size_t* return_capacity){
    *return_capacity = hashmap->capacity;
    return HASHMAP_SUCCESS;
}

void to_lower_case(char* key, size_t key_len){
    for (size_t i = 0; i < key_len; i++) {
        unsigned char c = (unsigned char)key[i];
        if (c >= 'A' && c <= 'Z') {
            key[i] = c - 'A' + 'a';
        }
    }
}

enum hashmap_error string_hashmap_put_case_insensitive(struct string_hashmap_t* hashmap, const char* key, const char* value, size_t key_len, size_t value_len){
    char* lower_key = malloc(sizeof(char) * (key_len + 1));
    if (!lower_key) return HASHMAP_ERROR_NO_MEMORY;
    memcpy(lower_key, key, key_len);
    lower_key[key_len] = '\0';

    to_lower_case(lower_key, key_len);

    enum hashmap_error put_result = string_hashmap_put(hashmap, lower_key, value, key_len, value_len);
    free(lower_key);
    return put_result;
}

enum hashmap_error string_hashmap_get_case_insensitive(const struct string_hashmap_t* hashmap, const char* key, size_t key_len, char** return_value){
    char* lower_key = malloc(sizeof(char) * (key_len + 1));
    if (!lower_key) return HASHMAP_ERROR_NO_MEMORY;
    memcpy(lower_key, key, key_len);
    lower_key[key_len] = '\0';

    to_lower_case(lower_key, key_len);
    
    enum hashmap_error get_result = string_hashmap_get(hashmap, lower_key, key_len, return_value);
    free(lower_key);
    return get_result;
}

enum hashmap_error string_hashmap_foreach(const struct string_hashmap_t* hashmap, string_hashmap_foreach_cb callback, void* user_data){
    if (!hashmap || !callback) {
        return HASHMAP_ERROR_INVALID_ARG;
    }

    for (size_t i = 0; i < hashmap->capacity; i++){
        struct node* curr = hashmap->arr_map[i];
        while (curr != NULL){
            int stop = callback(curr->key, curr->key_len, curr->value, curr->value_len, user_data);
            if (stop) {
                return HASHMAP_ERROR_STOP_ITERATION;
            }
            curr = curr->next;
        }
    }
    return HASHMAP_SUCCESS;
}