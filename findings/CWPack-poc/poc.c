/* Minimal PoC: the SIMPLEST documented CWPack stream-unpack loop over an
   untrusted, truncated MessagePack buffer. No skip logic, no tricks — just
   init_stream_unpack_context + cw_unpack_next until not-OK. */
#include <stdio.h>
#include <string.h>
#include "basic_contexts.h"

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 0;
    stream_unpack_context suc;
    memset(&suc, 0, sizeof(suc));
    init_stream_unpack_context(&suc, 16, f);   /* small buffer forces refill path */
    while (suc.uc.return_code == CWP_RC_OK) {
        cw_unpack_next((cw_unpack_context*)&suc);
    }
    terminate_stream_unpack_context(&suc);
    fclose(f);
    return 0;
}
