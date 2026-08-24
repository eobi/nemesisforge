#include <stdint.h>
#include <stddef.h>
#include "cJSON.h"
int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){ if(n>1000000)return 0;
  cJSON*j=cJSON_ParseWithLength((const char*)d,n); if(j)cJSON_Delete(j); return 0; }
