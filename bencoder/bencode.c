/*
Streaming bencode parser
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "bencode.h"

#define BENCODE_FAIL(msg) \
    do { fprintf(stderr, "bencode error: %s\n", msg); return 0; } while (0)

static bencode_frame_t *frame_new()
{
    bencode_frame_t *f = calloc(1, sizeof(bencode_frame_t));
    if (!f) return NULL;
    f->type = BENCODE_NONE;
    f->intval = 0;
    f->strval = NULL;
    f->strlen = 0;
    f->strcap = 0;
    f->key = NULL;
    f->keycap = 0;
    return f;
}

bencode_t *bencode_new(size_t nframes, 
                    bencode_callbacks_t *cbs,
                    void *u)
{
    bencode_t *me = calloc(1, sizeof(bencode_t));
    if (!me) return NULL;
    me->stk = calloc(nframes, sizeof(bencode_frame_t *));
    if (!me->stk) {free(me); return NULL;}
    me->stkcap = nframes;
    me->cbs = cbs;
    me->u = u;

    me->stk[0] = frame_new();
    me->stklen = 1;
    return me;
}

void bencode_free(bencode_t *me) 
{
    if (!me) return;
    if (me->stk) {
        for (size_t i=0; i < me->stklen; i++) {
            bencode_frame_t *f = me->stk[i];
            if (!f) continue;
            if (f->strval) free(f->strval);
            if (f->key) free(f->key);
            free(f);
        }
        free(me->stk);
    }
    free(me);
}

static bencode_frame_t *top(bencode_t *me)
{
    return me->stklen > 0 ? me->stk[me->stklen - 1] : NULL;
}

static int push(bencode_t *me)
{
    if(me->stklen == me->stkcap) {
        size_t newcap = me->stkcap * 2;
        bencode_frame_t **newstk = realloc(me->stk, newcap * sizeof(bencode_frame_t *));
        if (!newstk) return -1;
        me->stk = newstk;
        me->stkcap = newcap;
    }
    bencode_frame_t *f = frame_new();
    if(!f) return -1;
    me->stk[me->stklen++] = f;
    return 0;
}
static void pop(bencode_t *me)
{
    if (me->stklen == 0) return;
    bencode_frame_t *f = me->stk[me->stklen - 1];
    if (f->strval) { free(f->strval); f->strval = NULL; }
    if (f->key) {
        free(f->key);
        f->key = NULL;
    }
    free(f);
    me->stklen--;
}

static int append_char(bencode_frame_t *f, char c)
{
    if (f->strlen + 1 >= f->strcap) {
        size_t newcap = f->strcap ? f->strcap * 2 : 16;
        char *newbuf = realloc(f->strval, newcap);
        if (!newbuf) return -1;
        f->strval = newbuf;
        f->strcap = newcap;
    }
    f->strval[f->strlen++] = c;
    return 0;
}

static void call_hit_int(bencode_t *me, long long v)
{
    if (me->cbs && me->cbs->hit_int)
    me->cbs->hit_int(v, me->u);
}

static void call_hit_str(bencode_t *me, const char *s, size_t len)
{
    if (me->cbs && me->cbs->hit_str)
    me->cbs->hit_str(s, len, me->u);
}

static void call_dict_enter(bencode_t *me)
{
    if (me->cbs && me->cbs->dict_enter)
    me->cbs->dict_enter(me->u);
}
static void call_dict_leave(bencode_t *me)
{
    if (me->cbs && me->cbs->dict_leave)
    me->cbs->dict_leave(me->u);
}
static void call_list_enter(bencode_t *me)
{
    if (me->cbs && me->cbs->list_enter)
    me->cbs->list_enter(me->u);
}
static void call_list_leave(bencode_t *me)
{
    if (me->cbs && me->cbs->list_leave)
    me->cbs->list_leave(me->u);
}
static void call_dict_key(bencode_t *me, const char *s, size_t len)
{
    if (me->cbs && me->cbs->dict_key)
    me->cbs->dict_key(s, len, me->u);
}

static int __parse_digit(bencode_frame_t *f, char c) 
{
    if(c<'0' || c>'9') return -1;
    f->intval = f->intval * 10 + (c-'0');
    return 0;
}

int bencode_dispatch_from_buffer(bencode_t *me,
                                        const void *buf, size_t len)
{
    const char *s = buf;
    for(size_t i = 0; i <len; i++)
    {
        char c = s[i];
        bencode_frame_t *f = top(me);
        if (!f) BENCODE_FAIL("empty stack");
        switch (f->type) {
            case BENCODE_NONE:
            if (c == 'd') {
                f->type = BENCODE_DICT;
                call_dict_enter(me);
                push(me);
            }
            else if (c == 'l') {
                f->type = BENCODE_LIST; 
                call_list_enter(me);
                push(me);
            }
            else if (c == 'i')
            {
                f->type = BENCODE_INT; 
                f->intval = 0;
                f->negative = 0;
            }
            else if (isdigit((unsigned char)c)) {
                f->type = BENCODE_STRLEN;
                f->intval = (c - '0');

            } else {
                BENCODE_FAIL("unexpected char at root");
            }
            break;
            
            case BENCODE_INT:
            if (c == '-') {
                if (f->intval != 0) BENCODE_FAIL("invalid '-' in int");
                f->negative = 1;
            }
            else if (c == 'e') {
                long long v = f->negative ? -f->intval : f->intval;
                call_hit_int(me, v);
                pop(me);
            }
            else {
                if (__parse_digit(f, c) != 0)
                BENCODE_FAIL("bad int digit");
            }
            break;
            
            case BENCODE_STRLEN:
            if(isdigit((unsigned char)c)) {
                if(__parse_digit(f, c) != 0)
                BENCODE_FAIL("bad strlen digit");
            }
            else if (c == ':') {
                f->type = BENCODE_STRING;
                f->strlen = 0;
                f->strcap = (size_t)f->intval + 1;
                f->strval = malloc(f->strcap);
                if (!f->strval) return 0;
            } else {
                BENCODE_FAIL("bad strlen");
            }
            break;

            case BENCODE_STRING:
            if (f->strlen < (size_t)f->intval) {
                f->strval[f->strlen++] = c;
                if (f->strlen == (size_t)f->intval) {
                    call_hit_str(me, f->strval, f->strlen);
                    pop(me);
                }
            }
            break;

            case BENCODE_DICT:
            case BENCODE_LIST:
                if ( c == 'e') {
                    if (f->type == BENCODE_DICT) call_dict_leave(me);
                    else call_list_leave(me);
                    pop(me);
                } else {
                    push(me);
                    me->stk[me->stklen - 1]->type = BENCODE_NONE;
                    i--;
                }
                break;
                default: 
                BENCODE_FAIL("invalid parser state");
        }
    }
    return 1;

}