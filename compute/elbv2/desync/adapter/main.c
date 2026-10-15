/* Out-of-process binding to the pinned official aws/http-desync-guardian ABI.
 * No request-safety logic lives here: the library receives the complete original
 * HTTP/1 request line and headers, with their bytes, spelling and whitespace.
 * stdin: big-endian u32 size, followed by size raw bytes (1..65536).
 * stdout: greeting once, then u32 tier, u32 reason, u32 message_size, message.
 * Any malformed protocol, library failure or output failure terminates the worker.
 */
#include <stdint.h>
#include <stdio.h>
#include "http_desync_guardian.h"

#define MAX_HEADER_BYTES 65536u
#define SOURCE_REVISION "f0b15a772926ca47cf6216c73df8cfeaae02cd75"

static uint32_t decode_u32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void encode_u32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

int main(void) {
    unsigned char raw[MAX_HEADER_BYTES];
    unsigned char frame[12];
    const char greeting[] = "STACKD-HDG/1 " SOURCE_REVISION "\n";
    if (fwrite(greeting, 1, sizeof(greeting) - 1, stdout) != sizeof(greeting) - 1 ||
        fflush(stdout) != 0) {
        return 1;
    }
    for (;;) {
        size_t count = fread(frame, 1, 4, stdin);
        if (count == 0 && feof(stdin)) {
            return 0;
        }
        if (count != 4) {
            return 2;
        }
        uint32_t size = decode_u32(frame);
        if (size == 0 || size > MAX_HEADER_BYTES || fread(raw, 1, size, stdin) != size) {
            return 2;
        }
        http_desync_guardian_verdict_t verdict = {0};
        http_desync_guardian_analyze_raw_request(size, raw, &verdict);
        if ((uint32_t)verdict.tier > HTTP_DESYNC_GUARDIAN_REQUEST_SAFETY_TIER_T_SEVERE ||
            verdict.message_length >= HTTP_DESYNC_GUARDIAN_MESSAGE_MAX_SIZE) {
            return 3;
        }
        encode_u32(frame, (uint32_t)verdict.tier);
        encode_u32(frame + 4, (uint32_t)verdict.reason);
        encode_u32(frame + 8, verdict.message_length);
        if (fwrite(frame, 1, sizeof(frame), stdout) != sizeof(frame) ||
            fwrite(verdict.message_data, 1, verdict.message_length, stdout) != verdict.message_length ||
            fflush(stdout) != 0) {
            return 1;
        }
    }
}
