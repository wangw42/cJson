#ifndef WJSON_H__
#define WJSON_H__

#include <stddef.h>

typedef enum {
	W_NULL, W_FALSE, W_TRUE, W_NUMBER, W_STRING, W_ARRAY, W_OBJECT
}w_type;

typedef struct w_value w_value;
typedef struct w_member w_member;

struct w_value{
	union {
        struct { w_member* m; size_t size; }o;   /* object: members, member count */
        struct { w_value* e; size_t size; }a;    /* array:  elements, element count */
        struct { char* s; size_t len; }s;           /* string: null-terminated string, string length */
        double n;                           /* number */
    }u;
	w_type type;
}w_value;

struct w_member {
    char* k; size_t klen;   /* member key string, key string length */
    w_value v;           /* member value */
};

enum {
	W_PARSE_OK = 0,
    W_PARSE_EXPECT_VALUE,
    W_PARSE_INVALID_VALUE,
    W_PARSE_ROOT_NOT_SINGULAR,
    W_PARSE_NUMBER_TOO_BIG,
    W_PARSE_MISS_QUOTATION_MARK,
    W_PARSE_INVALID_STRING_ESCAPE,
    W_PARSE_INVALID_STRING_CHAR,
    W_PARSE_INVALID_UNICODE_HEX,
    W_PARSE_INVALID_UNICODE_SURROGATE,
    W_PARSE_MISS_COMMA_OR_SQUARE_BRACKET,
    W_PARSE_MISS_KEY,
    W_PARSE_MISS_COLON,
    W_PARSE_MISS_COMMA_OR_CURLY_BRACKET
};

#define w_init(v) do { (v)->type = W_NULL; } while(0)

int w_parse(w_value* v, const char* json);

void w_free(w_value* v);

w_type w_get_type(const  w_value* v);

#define w_set_null(v) w_free(v)

int w_get_boolean(const w_value* v);
void w_set_boolean(w_value* v, int b);

double w_get_number(const w_value* v);
void w_set_number(w_value* v, double n);

const char* w_get_string(const w_value* v);
size_t w_get_string_length(const w_value* v);
void w_set_string(w_value* v, const char* s, size_t len);

size_t w_get_array_size(const w_value* v);
w_value* w_get_array_element(const w_value* v, size_t index);

size_t w_get_object_size(const w_value* v);
const char* w_get_object_key(const w_value* v, size_t index);
size_t w_get_object_key_length(const w_value* v, size_t index);
w_value* w_get_object_value(const w_value* v, size_t index);

#endif