/* A width-times-depth truncation, the shape that produces most image-decoder
 * overflows. The row stride is computed in 32 bits and stored in 16, so a large
 * width truncates the allocation to a small number while the copy still uses the
 * full value.
 *
 *   width 0x8000, 16 bits per pixel  ->  0x8000 * 2 = 0x10000
 *   stored in a uint16_t             ->  0
 *   allocation guard turns 0 into 1  ->  a 1-byte buffer receives 65,536 bytes
 *
 * Build and run:   python -m forge lab examples/harness_trunc.c --fuzz-time 60
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    unsigned int width = (unsigned)data[0] | ((unsigned)data[1] << 8);
    unsigned int bpp   = data[2];
    if (bpp == 0 || bpp % 8) return 0;

    unsigned int row_true = width * (bpp / 8);   /* the honest answer */
    uint16_t     row_16   = (uint16_t)row_true;  /* the box that is too small */

    char *buf = malloc(row_16 ? row_16 : 1);
    if (!buf) return 0;
    volatile size_t n = row_true;                /* volatile: not folded away */
    memset(buf, 'A', n);                         /* the overflow */
    volatile char sink = buf[0];                 /* consumed, so not dead */
    (void)sink;
    free(buf);
    return 0;
}
