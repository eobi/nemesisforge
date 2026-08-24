#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define NANOSVG_IMPLEMENTATION
#include "nanosvg.h"
int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){ if(n>65536)return 0;
  char*s=(char*)malloc(n+1); if(!s)return 0; memcpy(s,d,n); s[n]=0;
  NSVGimage*im=nsvgParse(s,"px",96.0f); if(im)nsvgDelete(im); free(s); return 0; }
