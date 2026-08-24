#include <stdint.h>
#include <stddef.h>
#include "frozen.h"
static void cb(void*u,const char*n,size_t nl,const char*p,const struct json_token*t){(void)u;(void)n;(void)nl;(void)p;(void)t;}
int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){ if(n>65536)return 0;
  json_walk((const char*)d,n,cb,0); return 0; }
