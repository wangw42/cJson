#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "cJson.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef W_PARSE_STACK_INIT_SIZE
#define W_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)  do{assert(*c->json == (ch)); c->json++;} while(0)
#define ISDIGIT(ch)    ((ch)>='0' && (ch)<='9')
#define ISDIGIT1TO9(ch)   ((ch)>='1' && (ch)<='9')
#define PUTC(c, ch)         do { *(char*)w_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct {
	const char* json;
    char* stack;
    size_t size, top;
}w_context;

static void* w_context_push(w_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = W_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* w_context_pop(w_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void w_parse_space(w_context *c){
	const char *p = c->json;
	while(*p==' ' || *p=='\t' || *p=='\n' || *p=='\r'){
		p++;
	}
	c->json = p;
}

//true false null 
static int w_parse_literal(w_context* c, w_value* v, const char* literal, w_type type){
	size_t i;
	EXPECT(c, literal[0]);
	for(i = 0; literal[i+1]; i++){
		if(c->json[i] != literal[i+1]){
			return W_PARSE_INVALID_VALUE;
		}
	}
	c->json += i;
	v->type = type;
	return W_PARSE_OK;
}

static int w_parse_number(w_context* c, w_value* v){
	const char* p = c->json;
	if(*p == '-') p++;
	if(*p == '0') p++;
	else{
		if(!ISDIGIT1TO9(*p)) return W_PARSE_INVALID_VALUE; 
		for(p++; ISDIGIT(*p); p++);
	}
	if(*p == '.'){
		p++;
		if(!ISDIGIT(*p)) return W_PARSE_INVALID_VALUE;
		for (p++; ISDIGIT(*p); p++);
	}
	if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return W_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    errno = 0;
    v->u.n = strtod(c->json, NULL); // char* to double
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) //errno.h and math.h
        return W_PARSE_NUMBER_TOO_BIG;
    v->type = W_NUMBER;
    c->json = p;
    return W_PARSE_OK;

}

//解析 4 位十六进数字
static const char* w_parse_hex4(const char* p, unsigned* u) {
    int i;
    *u = 0;
    for (i = 0; i < 4; i++) {
        char ch = *p++;
        *u <<= 4;
        if      (ch >= '0' && ch <= '9')  *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F')  *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f')  *u |= ch - ('a' - 10);
        else return NULL;
    }
    return p;
}

//utf-8
/* eg.
欧元符号 € → U+20AC：
* U+20AC 在 U+0800 ~ U+FFFF 的范围内，应编码成 3 个字节。
* U+20AC 的二进位为 10000010101100
* 3 个字节的情况我们要 16 位的码点，所以在前面补两个 0，成为 0010000010101100
* 按上表把二进位分成 3 组：0010, 000010, 101100
* 加上每个字节的前缀：11100010, 10000010, 10101100
* 用十六进位表示即：0xE2, 0x82, 0xAC
*/
static void w_encode_utf8(w_context* c, unsigned u) {
    if (u <= 0x7F) 
        PUTC(c, u & 0xFF);
    else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | ( u       & 0x3F));
    }
    else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF)); // 0xE0 = 11100000 
        PUTC(c, 0x80 | ((u >>  6) & 0x3F)); // 0x80 = 10000000
        PUTC(c, 0x80 | ( u        & 0x3F)); // 0x3F = 00111111
    }
    else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int w_parse_string_raw(w_context* c, char** str, size_t* len) {
    size_t head = c->top;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = (char*)w_context_pop(c, *len);
                c->json = p;
                return W_PARSE_OK;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = w_parse_hex4(p, &u)))
                            STRING_ERROR(W_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                            if (*p++ != '\\')
                                STRING_ERROR(W_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(W_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = w_parse_hex4(p, &u2)))
                                STRING_ERROR(W_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(W_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        w_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(W_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(W_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(W_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int w_parse_string(w_context* c, w_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = w_parse_string_raw(c, &s, &len)) == W_PARSE_OK)
        w_set_string(v, s, len);
    return ret;
}

static int w_parse_array(w_context* c, w_value* v);
static int w_parse_object(w_context* c, w_value* v); 

static int w_parse_value(w_context* c, w_value* v) {
    switch (*c->json) {
        case 't':  return w_parse_literal(c, v, "true", W_TRUE);
        case 'f':  return w_parse_literal(c, v, "false", W_FALSE);
        case 'n':  return w_parse_literal(c, v, "null", W_NULL);
        default:   return w_parse_number(c, v);
        case '"':  return w_parse_string(c, v);
        case '[':  return w_parse_array(c, v);
        case '{':  return w_parse_object(c, v);
        case '\0': return W_PARSE_EXPECT_VALUE;
    }
}

static int w_parse_array(w_context* c, w_value* v) {
    size_t i, size = 0;
    int ret;
    EXPECT(c, '[');
    w_parse_space(c);
    if (*c->json == ']') {
        c->json++;
        v->type = W_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return W_PARSE_OK;
    }
    for (;;) {
        w_value e;
        w_init(&e);
        if ((ret = w_parse_value(c, &e)) != W_PARSE_OK)
            break;
        memcpy(w_context_push(c, sizeof(w_value)), &e, sizeof(w_value));
        size++;
        w_parse_space(c);
        if (*c->json == ',') {
            c->json++;
            w_parse_space(c);
        }
        else if (*c->json == ']') {
            c->json++;
            v->type = W_ARRAY;
            v->u.a.size = size;
            size *= sizeof(w_value);
            memcpy(v->u.a.e = (w_value*)malloc(size), w_context_pop(c, size), size);
            return W_PARSE_OK;
        }
        else {
            ret = W_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* Pop and free values on the stack */
    for (i = 0; i < size; i++)
        w_free((w_value*)w_context_pop(c, sizeof(w_value)));
    return ret;
}

static int w_parse_object(w_context* c, w_value* v) {
    size_t i, size;
    w_member m;
    int ret;
    EXPECT(c, '{');
    w_parse_space(c);
    if (*c->json == '}') {
        c->json++;
        v->type = W_OBJECT;
        v->u.o.m = 0;
        v->u.o.size = 0;
        return W_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    for (;;) {
        char* str;
        w_init(&m.v);
        /* parse key */
        if (*c->json != '"') {
            ret = W_PARSE_MISS_KEY;
            break;
        }
        if ((ret = w_parse_string_raw(c, &str, &m.klen)) != W_PARSE_OK)
            break;
        memcpy(m.k = (char*)malloc(m.klen + 1), str, m.klen);
        m.k[m.klen] = '\0';
        /* parse ws colon ws */
        w_parse_space(c);
        if (*c->json != ':') {
            ret = W_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        w_parse_space(c);
        /* parse value */
        if ((ret = w_parse_value(c, &m.v)) != W_PARSE_OK)
            break;
        memcpy(w_context_push(c, sizeof(w_member)), &m, sizeof(w_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        /* parse ws [comma | right-curly-brace] ws */
        w_parse_space(c);
        if (*c->json == ',') {
            c->json++;
            w_parse_space(c);
        }
        else if (*c->json == '}') {
            size_t s = sizeof(w_member) * size;
            c->json++;
            v->type = W_OBJECT;
            v->u.o.size = size;
            memcpy(v->u.o.m = (w_member*)malloc(s), w_context_pop(c, s), s);
            return W_PARSE_OK;
        }
        else {
            ret = W_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    /* Pop and free members on the stack */
    free(m.k);
    for (i = 0; i < size; i++) {
        w_member* m = (w_member*)w_context_pop(c, sizeof(w_member));
        free(m->k);
        w_free(&m->v);
    }
    v->type = W_NULL;
    return ret;
}

int w_parse(w_value* v, const char* json) {
    w_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    w_init(v);
    w_parse_space(&c);
    if ((ret = w_parse_value(&c, v)) == W_PARSE_OK) {
        w_parse_space(&c);
        if (*c.json != '\0') {
            v->type = W_NULL;
            ret = W_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

void w_free(w_value* v) {
    size_t i;
    assert(v != NULL);
    switch (v->type) {
        case W_STRING:
            free(v->u.s.s);
            break;
        case W_ARRAY:
            for (i = 0; i < v->u.a.size; i++)
                w_free(&v->u.a.e[i]);
            free(v->u.a.e);
            break;
        case W_OBJECT:
            for (i = 0; i < v->u.o.size; i++) {
                free(v->u.o.m[i].k);
                w_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
            break;
        default: break;
    }
    v->type = W_NULL;
}

w_type w_get_type(const w_value* v) {
    assert(v != NULL);
    return v->type;
}

int w_get_boolean(const w_value* v) {
    assert(v != NULL && (v->type == W_TRUE || v->type == W_FALSE));
    return v->type == W_TRUE;
}

void w_set_boolean(w_value* v, int b) {
    w_free(v);
    v->type = b ? W_TRUE : W_FALSE;
}

double w_get_number(const w_value* v) {
    assert(v != NULL && v->type == W_NUMBER);
    return v->u.n;
}

void w_set_number(w_value* v, double n) {
    w_free(v);
    v->u.n = n;
    v->type = W_NUMBER;
}

const char* w_get_string(const w_value* v) {
    assert(v != NULL && v->type == W_STRING);
    return v->u.s.s;
}

size_t w_get_string_length(const w_value* v) {
    assert(v != NULL && v->type == W_STRING);
    return v->u.s.len;
}

void w_set_string(w_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    w_free(v);
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = W_STRING;
}

size_t w_get_array_size(const w_value* v) {
    assert(v != NULL && v->type == W_ARRAY);
    return v->u.a.size;
}

w_value* w_get_array_element(const w_value* v, size_t index) {
    assert(v != NULL && v->type == W_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

size_t w_get_object_size(const w_value* v) {
    assert(v != NULL && v->type == W_OBJECT);
    return v->u.o.size;
}

const char* w_get_object_key(const w_value* v, size_t index) {
    assert(v != NULL && v->type == W_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t w_get_object_key_length(const w_value* v, size_t index) {
    assert(v != NULL && v->type == W_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

w_value* w_get_object_value(const w_value* v, size_t index) {
    assert(v != NULL && v->type == W_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}
