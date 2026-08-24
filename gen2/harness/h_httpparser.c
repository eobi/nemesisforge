#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "http_parser.h"
int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){ if(n>65536)return 0;
  struct http_parser_url u; http_parser_url_init(&u);
  http_parser_parse_url((const char*)d,n,0,&u); return 0; }
