#include "myIso8583.h"
 

// =========================================================================
void bytes_to_hex (const unsigned char *bytes, int len, char *out) {
    for (int i = 0; i < len; i++) {
        sprintf (out + i * 2, "%02X", bytes[i]);
    }
    out[len * 2] = '\0';
}

// =========================================================================
static int test_bit (const unsigned char *bitmap, int bit){
    return (bitmap[ (bit - 1) / 8] & (1 << (7 - ((bit - 1) % 8)))) != 0;
}

// =========================================================================
static int has_secondary_bitmap (const unsigned char *bitmap) {
    return (bitmap[0] & 0x80) != 0;
}

// =========================================================================
/* Util: define bit no bitmap (1..64) */
static void set_bitmap_bit(uint8_t bitmap[16], int bitno){
    if(bitno < 1 || bitno > 128) 
        return;
    int idx = (bitno - 1) / 8;
    int pos = 7 - ((bitno - 1) % 8); // MSB is bit 1
    bitmap[idx] |= (1 << pos);
}


// =========================================================================
/* funcao que retorna o tamanho do bitmap baseado no bit 1 do bitmap  */
int bitmap_size (ISO8583 *iso) {
    return (iso->bitmap[0] & 0x80) ? 16 : 8;
}


// =========================================================================
/* funcao que retorna o tamanho do bitmap baseado no bit 1 do bitmap  */
int is_bit1_set (ISO8583 *iso) {
    return (iso->bitmap[0] & 0x80) != 0;
}

// =========================================================================
/* Inicializa MTI */
void iso_set_mti(ISO8583 *iso, const char *mti4){
    if(strlen(mti4) != 4) 
        return;
    memcpy(iso->mti, mti4, 4);
    iso->mti[4] = '\0';
}


// =========================================================================
/* Monta a mensagem: MTI(4 ASCII) + bitmap(8 bytes binary) + campos */
int iso_build_message(ISO8583 *iso, uint8_t *outbuf, int outbuf_len){
    if(strlen(iso->mti) != 4)
        return -1;

    int pos = 0;
 
    printf("iso_build_message outbuf_len [%d]\n", outbuf_len);

    // MTI (4 bytes ASCII)
    if(pos + 4 > outbuf_len) 
        return -1;

    memcpy(outbuf + pos, iso->mti, 4); 
        pos += 4;

    int tam_bitmap = bitmap_size (iso);
    printf("bitmap_size [%d]\n", bitmap_size);
    int has_secondary = 0;

    for (int i = 65; i < 129; i++) {
        if (iso->fields[i].present) {
            has_secondary = 1;
            printf("Tem bit secundario\n");
            break;
        }
    }

    if (has_secondary) {
            printf("Tem bit secundario\n");
        set_bitmap_bit(iso->bitmap,1);
    }

    int bitmap_len = has_secondary ? 16 : 8;
    printf("bitmap_len [%d]\n", bitmap_len);
    memcpy(outbuf + pos, iso->bitmap, bitmap_len); 
    pos += bitmap_len;

    // Bitmap (16 bytes binary)
    if(pos + 16 > outbuf_len) 
        return -1;

    //memcpy(outbuf + pos, iso->bitmap, 16); 
    //pos += 16;

    // Adiciona Campos
    for(int i = 1; i < MAX_FIELDS; ++i){
        Field *f = &iso->fields[i];
        if(!f->present)
            continue;

        if(f->is_llvar){
            printf("llvar\n");
            // comprimento como 2 dígitos ASCII
            if(pos + 2 + f->len > outbuf_len) 
                return -1;
            int len_tens = f->len / 10;
            int len_ones = f->len % 10;
            outbuf[pos++] = '0' + len_tens;
            outbuf[pos++] = '0' + len_ones;
            printf("iso_build_message outbuf [%02d]\n", f->len);
            memcpy(outbuf + pos, f->data, f->len); 
            pos += f->len;
        } else if (f->is_lllvar) {
            // comprimento como 3 dígitos ASCII
            printf("lllvar\n");
            if(pos + 3 + f->len > outbuf_len) 
                return -1;
            int len_hunds = f->len / 100;
            int len_tens = f->len / 10;
            int len_ones = f->len % 10;
            outbuf[pos++] = '0' + len_hunds;
            outbuf[pos++] = '0' + len_tens;
            outbuf[pos++] = '0' + len_ones;
            printf("iso_build_message outbuf [%03d]\n", f->len);
            memcpy(outbuf + pos, f->data, f->len); 
            pos += f->len;
        } else {
            // campo fixo: só coloca os dados
            if(pos + f->len > outbuf_len) 
                return -1;
            memcpy(outbuf + pos, f->data, f->len); 
            pos += f->len;
        }  
    }

    return pos; // tamanho da mensagem montada
}

// =========================================================================
/*int build_bitmap (ISO8583 *fields, unsigned char *bitmap) {
    memset (bitmap, 0, 16);
    int has_secondary = 0;

    for (int i = 2; i <= 128; i++) {
        if (fielsd[i].present {
            set_bitmap (bitmap, i);
            if (i > 64)
                has_secondary = 1;
        }
    }

    if (has_secondary)
        set_bitmap (bitmap, 1);

    return has_secondary ? 16 : 8;
} */

// =========================================================================
int parse_iso_message (const unsigned char *msg, int len, ISO8583 *iso) {
   if (len < 12) 
        return -1;

    memset(iso, 0, sizeof(*iso));
    memcpy(iso->mti, msg, 4);
    iso->mti[4] = '\0';
    memcpy(iso->bitmap, msg + 4, 8);
    int pos = 12;
    // verifica bitmap secundário
    if (has_secondary_bitmap(iso->bitmap)) {
        memcpy(iso->bitmap + 8, msg + pos, 8);
        pos += 8;
    }

    int max_field = has_secondary_bitmap(iso->bitmap) ? 128 : 64;

    for (int i = 2; i <= max_field && pos < len; i++) {
        if (!test_bit(iso->bitmap, i)) 
            continue;
        int flen = 0;
        // LLVAR / LLLVAR exemplos
        if (i == 2 || i == 102) {
            if (pos + 2 > len) 
                return -2;

            char lenstr[3] = {0};
            memcpy(lenstr, msg + pos, 2);
            flen = atoi(lenstr);
            printf("flen [%d] [%d]\n", i, flen);
            pos += 2;
        } else if (i == 48) {
            if (pos + 3 > len) 
                return -2;
            char lenstr[4] = {0};
            memcpy(lenstr, msg + pos, 3);
            flen = atoi(lenstr);
            printf("flen [%d] [%d]\n", i, flen);
            pos += 3;
        } else {
            switch (i) {
                case 3: flen = 6; break;
                case 4: flen = 12; break;
                case 7: flen = 10; break;
                case 11: flen = 6; break;
                case 12: flen = 6; break;
                case 37: flen = 12; break;
                case 41: flen = 8; break;
                case 49: flen = 3; break;
                default: flen = 0;
            }
        }

        if (flen > 0 && pos + flen <= len) {
            iso->fields[i].present = 1;
            iso->fields[i].len = flen;
            memcpy(iso->fields[i].data, msg + pos, flen);
            pos += flen;
        }
    }
    return 0;
}

// =========================================================================
/* debug: imprime buffer em hex e ASCII legível */
void print_hex_ascii(const uint8_t *buf, int len){
    for(int i=0;i<len;i++){
        printf("%02X ", buf[i]);
        if((i+1)%16==0) { 
            printf(" \n");
        }
    }

    printf("\nASCII: ");
    for(int i=0;i<len;i++){
        uint8_t c = buf[i];
        putchar((c >= 32 && c <=126) ? c : '.');
    }
    printf("\n");
}

// =========================================================================
void iso_copy_fields(const ISO8583 *src, ISO8583 *dst) {
    printf("Entrou no iso_copy_fields...\n");
    memset (dst, 0, sizeof(ISO8583));
    memcpy (dst->bitmap, src->bitmap, 16);

   int has_secondary = has_secondary_bitmap (dst->bitmap);

    int max_fields = has_secondary  ? 128 : 64;

    for (int i = 2; i < max_fields; i++) {
        if (src->fields[i].present) {
            dst->fields[i].present = 1;
            dst->fields[i].is_llvar = src->fields[i].is_llvar;
            dst->fields[i].is_lllvar = src->fields[i].is_lllvar;
            dst->fields[i].len = src->fields[i].len;
            dst->fields[i].data = malloc (src->fields[i].len);
            if (dst->fields[i].data)
                memcpy(dst->fields[i].data, src->fields[i].data, src->fields[i].len);
            set_bitmap_bit(dst->bitmap, i);
        }
    }
    printf("saindo do iso_copy_fields...\n");
}

// =========================================================================
void iso_free(ISO8583 *iso) {
    for (int i = 1; i < MAX_FIELDS; i++ ) {
        free(iso->fields[i].data);
        iso->fields[i].data = NULL;
        iso->fields[i].present = 0;
    }
}

// =========================================================================
static void iso_print (const ISO8583 *iso) {
    printf("MTI: %s\n", iso->mti);
    int has_secondary = has_secondary_bitmap (iso->bitmap);
    int max_fields = has_secondary  ? 128 : 64;
    for (int i = 2; i <= max_fields; i++) {
        if (iso->fields[i].present){
            printf("     F%03d: %.*s\n", i, iso->fields[i].len, iso->fields[i].data);
        }
    }
}

// =========================================================================
int build_iso_response(const ISO8583 *req, unsigned char *out) {
    ISO8583 resp;
    memset(&resp, 0, sizeof(resp));

    // muda o MTI para 0210
    strcpy(resp.mti, "0210");

    // copia campos do request
    iso_copy_fields(req, &resp);

    // adiciona campo 39 = "00" (sucesso)
    set_bitmap_bit (resp.bitmap, 39);
    resp.fields[39].present = 1;
    strcpy(resp.fields[39].data, "00");
    resp.fields[39].len = 2;

    unsigned char *ptr = out;
    memcpy(ptr, resp.mti, 4); ptr += 4;
    int has2 = has_secondary_bitmap (resp.bitmap);
    int bmp_len = has2 ? 16 : 8;
    memcpy(ptr, resp.bitmap, bmp_len);
    ptr += bmp_len;

    for (int i = 2; i <= (has2 ? 128 : 64); i++) {
        if (resp.fields[i].present) {
            if (i == 2 || i == 102) {
                sprintf((char*)ptr, "%02d", resp.fields[i].len);
                ptr += 2;
            } else if (i == 48) {
                sprintf((char*)ptr, "%03d", resp.fields[i].len);
                ptr += 3;
            }

            memcpy(ptr, resp.fields[i].data, resp.fields[i].len);
            ptr += resp.fields[i].len;
        }
    }
    return ptr - out;
}

// =========================================================================
void printa_iso(const ISO8583 *iso) {
    printf("MTI: %s\n", iso->mti);
    int max_field = has_secondary_bitmap(iso->bitmap) ? 128 : 64;
    for (int i = 2; i < max_field; i++) {
        if (iso->fields[i].present)
            printf("       F%03d: %.*s\n", i, iso->fields[i].len, iso->fields[i].data);
    }
}
