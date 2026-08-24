#include <stdint.h>
#include <stddef.h>
#define CGLTF_IMPLEMENTATION
#include "cgltf.h"
int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){ if(n>1000000)return 0;
  cgltf_options o; memset(&o,0,sizeof(o)); cgltf_data*out=0;
  if(cgltf_parse(&o,d,n,&out)==cgltf_result_success && out) cgltf_free(out); return 0; }
