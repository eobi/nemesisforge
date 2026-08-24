#include <stdint.h>
#include <stddef.h>
#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO
#include "stb_image.h"
int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){ if(n<8||n>(1u<<20))return 0;
  int x,y,c; stbi_uc*p=stbi_load_from_memory(d,(int)n,&x,&y,&c,0); if(p)stbi_image_free(p); return 0; }
