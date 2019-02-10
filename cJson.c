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
    v->n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
        return W_PARSE_NUMBER_TOO_BIG;
    v->type = W_NUMBER;
    c->json = p;
    return W_PARSE_OK;

}

static int w_parse_string(w_context* c, w_value* v) {
    size_t head = c->top, len;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                len = c->top - head;
                w_set_string(v, (const char*)w_context_pop(c, len), len);
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
                    default:
                        c->top = head;
                        return W_PARSE_INVALID_STRING_ESCAPE;
                }
                break;
            case '\0':
                c->top = head;
                return W_PARSE_MISS_QUOTATION_MARK;
            default:
                if ((unsigned char)ch < 0x20) { 
                    c->top = head;
                    return W_PARSE_INVALID_STRING_CHAR;
                }
                PUTC(c, ch);
        }
    }
}

static int w_parse_value(w_context* c, w_value* v) {
    switch (*c->json) {
        case 't':  return w_parse_literal(c, v, "true", W_TRUE);
        case 'f':  return w_parse_literal(c, v, "false", W_FALSE);
        case 'n':  return w_parse_literal(c, v, "null", W_NULL);
        default:   return w_parse_number(c, v);
        case '\0': return W_PARSE_EXPECT_VALUE;
    }
}

int w_parse(w_value* v, const char* json) {
    w_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    v->type = W_NULL;
    w_parse_whitespace(&c);
    if ((ret = w_parse_value(&c, v)) == W_PARSE_OK) {
        w_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = W_NULL;
            ret = W_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    return ret;
}

void w_free(w_value* v) {
    assert(v != NULL);
    if (v->type == W_STRING)
        free(v->u.s.s);
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
    return v->n;
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

