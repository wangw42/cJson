#ifndef WJSON_H__
#define WJSON_H__

typedef enum {
	W_NULL, W_FALSE, W_TRUE, W_NUMBER, W_STRING, W_ARRAY, W_OBJECT
}w_type;

typedef struct {
	double n;
	w_type type;
}w_value;

enum {
	W_PARSE_OK = 0,
    W_PARSE_EXPECT_VALUE,
    W_PARSE_INVALID_VALUE,
    W_PARSE_ROOT_NOT_SINGULAR,
    W_PARSE_NUMBER_TOO_BIG
};

int w_parse(w_value* v, const char* json);

w_type w_get_type(const  w_value* v);

double w_get_number(const w_value* v);

#endif