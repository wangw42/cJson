#ifndef WJSON_H__
#define WJSON_H__

#include <stddef.h>

typedef enum {
	W_NULL, W_FALSE, W_TRUE, W_NUMBER, W_STRING, W_ARRAY, W_OBJECT
}w_type;

typedef struct {
	union {
        struct { char* s; size_t len; }s;  /* string: null-terminated string, string length */
        double n;                          /* number */
    }u;
	w_type type;
}w_value;

enum {
	W_PARSE_OK = 0,
    W_PARSE_EXPECT_VALUE,
    W_PARSE_INVALID_VALUE,
    W_PARSE_ROOT_NOT_SINGULAR,
    W_PARSE_NUMBER_TOO_BIG,
    W_PARSE_MISS_QUOTATION_MARK,
    W_PARSE_INVALID_STRING_ESCAPE,
    W_PARSE_INVALID_STRING_CHAR
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

#endif