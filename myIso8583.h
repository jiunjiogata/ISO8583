#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define MAX_FIELDS 129 // 1..128 supported
#define MAX_MSG_LEN 8192

typedef struct {
    int present;
    int is_llvar; // 1 se LLVAR (comprimento variável com 2 dígitos ASCII)
    int is_lllvar; // 1 se LLLVAR (comprimento variável com 3 dígitos ASCII)
    int len;
    uint8_t *data; // bytes (não nulos)
} Field;

typedef struct {
    char mti[5]; // 4 chars + NUL
    uint8_t bitmap[16];
    Field fields[MAX_FIELDS];
} ISO8583;

/* Util: define bit no bitmap (1..64) */
void bytes_to_hex (const unsigned char *bytes, int len, char *out);
static int test_bit (const unsigned char *bitmap, int bit);
static int has_secondary_bitmap(const unsigned char *bitmap);
static void set_bitmap_bit(uint8_t bitmap[16], int bitno);
void iso_set_mti(ISO8583 *iso, const char *mti4);
int iso_set_field(ISO8583 *iso, int fnum, const char *value);
int iso_set_fields_llvar(ISO8583 *iso, int fnum, const char *value);
int iso_set_fields_lllvar(ISO8583 *iso, int fnum, const char *value);
int iso_build_message(ISO8583 *iso, uint8_t *outbuf, int outbuf_len);
int build_iso_message (char *out_msg, const char header, const char *mti, ISO8583 *iso);
void print_hex_ascii(const uint8_t *buf, int len);
void iso_free(ISO8583 *iso);
void iso_copy_fields(const ISO8583 *src, ISO8583 *dst);
static void iso_print (const ISO8583 *iso);
int parse_iso_message (const unsigned char *msg, int len, ISO8583 *ISO); 
int build_iso_response (const ISO8583 *req, unsigned char *out);
void printa_iso(const ISO8583 *iso);
