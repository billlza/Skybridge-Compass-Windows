#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#include <libavutil/common.h>

/* The provider uses bitwise saturation. Compare its explicitly narrowed return
 * values with an independent comparison-based reference, including extremes. */
static int check_value(int value)
{
    const int expected_u8 = value < 0 ? 0 : value > UINT8_MAX ? UINT8_MAX : value;
    const int expected_s8 = value < INT8_MIN ? INT8_MIN : value > INT8_MAX ? INT8_MAX : value;
    const int expected_u16 = value < 0 ? 0 : value > UINT16_MAX ? UINT16_MAX : value;
    const int expected_s16 = value < INT16_MIN ? INT16_MIN : value > INT16_MAX ? INT16_MAX : value;
    if (av_clip_uint8_c(value) != expected_u8 || av_clip_int8_c(value) != expected_s8 ||
        av_clip_uint16_c(value) != expected_u16 || av_clip_int16_c(value) != expected_s16) {
        fprintf(stderr, "Provider clipping mismatch for %d\n", value);
        return 1;
    }
    return 0;
}

int main(void)
{
    const int edges[] = {INT_MIN, INT_MIN + 1, -16777216, 16777216, INT_MAX - 1, INT_MAX};
    for (int value = -65537; value <= 65537; ++value)
        if (check_value(value)) return 1;
    for (size_t index = 0; index < sizeof(edges) / sizeof(edges[0]); ++index)
        if (check_value(edges[index])) return 1;
    puts("Provider clipping: 131081 inputs matched all four reference ranges.");
    return 0;
}
