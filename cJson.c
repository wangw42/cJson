#include "cJson.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>

#define EXPECT(c, ch)  do{assert(*c->json == (ch)); c->json++;} while(0)
#define ISDIGIT(ch)    ((ch)>='0' && (ch)<='9')
#define ISDIGIT1TO9    ((ch)>='1' && (ch)<='9')

typedef struct {
	const char* json;
}w_context;

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

w_type w_get_type(const w_value* v) {
    assert(v != NULL);
    return v->type;
}

double w_get_number(const w_value* v) {
    assert(v != NULL && v->type == W_NUMBER);
    return v->n;
}
