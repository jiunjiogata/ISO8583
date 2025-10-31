#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include "myIso8583.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8583
#define TIMEOUT_SECONDS 5

#define MAX_FIELDS 129
#define MAX_MSG_LEN 8192

// =========================================================================
static void clear_iso(ISO8583 *iso){
    memset(iso, 0, sizeof(ISO8583));
    iso->mti[0] = '\0';
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
/* Define campo fixo (ASCII) */
int iso_set_field(ISO8583 *iso, int fnum, const char *value){
    if(fnum < 1 || fnum >= MAX_FIELDS) 
        return -1;

    Field *f = &iso->fields[fnum];
    free(f->data);
    f->len = (int)strlen(value);
    f->data = malloc(f->len);

    if(!f->data) 
        return -1;

    memcpy(f->data, value, f->len);
    f->present = 1;
    f->is_llvar = 0;
    f->is_lllvar = 0;
    set_bitmap_bit(iso->bitmap, fnum);

    return 0;
}

/* Define campo LLVAR (2 dígitos de comprimento ASCII + dados) */
int iso_set_fields_llvar(ISO8583 *iso, int fnum, const char *value){
    if(fnum < 1 || fnum >= MAX_FIELDS) 
        return -1;

    int vlen = (int)strlen(value);

    if(vlen > 99) 
        return -1; // LLVAR limita a 99 aqui

    Field *f = &iso->fields[fnum];
    free(f->data);
    f->len = vlen;
    f->data = malloc(f->len);

    if(!f->data) 
        return -1;

    memcpy(f->data, value, f->len);
    f->present = 1;
    f->is_llvar = 1;
    f->is_lllvar = 0;
    set_bitmap_bit(iso->bitmap, fnum);
 
    printf(" Campo [%d] LLVAR presente\n", fnum);

    return 0;
}


// =========================================================================
/* Define campo LLLVAR (3 dígitos de comprimento ASCII + dados) */
int iso_set_fields_lllvar(ISO8583 *iso, int fnum, const char *value){
    if(fnum < 1 || fnum >= MAX_FIELDS) 
        return -1;

    int vlen = (int)strlen(value);

    //if(vlen < 99 || vlen > 999) 
    //    return -1; // LLLVAR tem que ser maior do que 99 e menor do que 999 

    Field *f = &iso->fields[fnum];
    free(f->data);
    f->len = vlen;
    f->data = malloc(f->len);

    if(!f->data) 
        return -1;

    memcpy(f->data, value, f->len);
    f->present = 1;
    f->is_llvar = 0;
    f->is_lllvar = 1;
    set_bitmap_bit(iso->bitmap, fnum);

    printf(" Campo [%d] LLLVAR presente\n", fnum);

    return 0;
}

// =========================================================================
/* Envia com header 2 bytes (big-endian) de comprimento e aguarda resposta com timeout */
int send_and_receive_iso(int sockfd, uint8_t *msg, int msglen, uint8_t *resp, int resp_maxlen) {
    // header de 2 bytes big-endian
    uint8_t hdr[2];
    uint16_t h = htons((uint16_t)msglen);
    hdr[0] = (h >> 8) & 0xFF;
    hdr[1] = h & 0xFF;

    uint16_t msg_len = ((hdr[1] << 8) | hdr[0]);
    printf("tamanho da mensagem enviada hdr [%02X %02X] = [%d]\n", hdr[1], hdr[0], msg_len);
    printf("\n\n");

    // envia header
    if (write(sockfd, hdr, 2) != 2) {
        perror("write header");
        return -1;
    }
    // envia corpo
    int sent = 0;
    while (sent < msglen) {
        int w = write(sockfd, msg + sent, msglen - sent);
        if (w <= 0) {
            perror("write body");
            return -1;
        }
        sent += w;
    }
    // aguarda resposta com select()
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SECONDS;
    tv.tv_usec = 0;

    int sel = select(sockfd + 1, &rfds, NULL, NULL, &tv);

    if (sel < 0) {
        perror("select");
        return -1;
    }

    if (sel == 0) {
        fprintf(stderr, "Timeout aguardando resposta\n");
        return 0;
    }

    // lê header da resposta
    uint8_t hdr2[2];
    int r = read(sockfd, hdr2, 2);
    if (r != 2) {
        perror("read resp header");
        return -1;
    }

    uint16_t resp_len_resp = ((hdr2[1] << 8) | hdr2[0]);
    if (resp_len_resp > MAX_MSG_LEN) {
        fprintf(stderr, "Resposta muito grande: %u bytes\n", resp_len_resp);
        return -1;
    }

    printf("tamanho da mensagem recebida hdr [%02X %02X] = [%d]\n", hdr2[1], hdr2[0], resp_len_resp);

    int recvd = 0;

    while (recvd < resp_len_resp) {
        int nr = read(sockfd, resp + recvd, resp_len_resp - recvd);
            if (nr <= 0) {
            perror("read resp body");
            return -1;
        }

        recvd += nr;
        printf ("recvd [%d]\n", recvd);
    }

    resp_maxlen = recvd;
    return recvd;
}

int main(){
    ISO8583 iso;
    clear_iso(&iso);
    uint8_t resposta[MAX_MSG_LEN];
    int resp, resplen;
    int sockfd;
    struct sockaddr_in serv;

    // MTI 0200 (Transaction request)
    iso_set_mti(&iso, "0200");

    // Exemplos de campos (campo 2 é LLVAR - PAN)
    iso_set_fields_llvar(&iso, 2, "1234567890123456"); // Primary Account Number (LLVAR)
    iso_set_field(&iso, 3, "000000"); // Processing Code (6)
    iso_set_field(&iso, 4, "000000010000"); // Amount, 12 (ex: 100.00 -> "000000010000")
    iso_set_field(&iso, 11, "123456"); // STAN (6)
    iso_set_field(&iso, 41, "TERMID01"); // Terminal ID (8)
    iso_set_field(&iso, 49, "986"); // Currency code (3 - BRL)
    //iso_set_fields_llvar(&iso, 128, "123456789012345678901234567890123456789012345678901234567890-12345678901234567890123456789012345678901234567890"); // Currency code (3 - BRL)
    iso_set_fields_lllvar(&iso, 128, "12345678"); // Currency code (3 - BRL)


    uint8_t msg[MAX_MSG_LEN];
    int msglen = iso_build_message(&iso, msg, sizeof(msg));

    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&serv, 0, sizeof(serv));

    serv.sin_family = AF_INET;
    serv.sin_port = htons(SERVER_PORT);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);    

    if (inet_pton(AF_INET, SERVER_IP, &serv.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    if(msglen < 0){
        fprintf(stderr, "Erro ao montar a mensagem\n");
        return 1;
    }

    printf("Mensagem montada: %d bytes\n", msglen);
    print_hex_ascii(msg, msglen);

    //unsigned char hdr[2];
    //hdr[0] = (msglen >> 8) & 0xFF;
    //hdr[1] = msglen  & 0xFF;

    //send (sockfd, hdr, 2, 0);
    //printf("Enviando header [%c ]\n", hdr[0]);
    //printf("Enviando header [%c ]\n", hdr[1]);

    //send (sockfd, msg, msglen, 0);
    //printf("Mensagem 0200 enviada [%d bytes)\n", msglen);

    //unsigned char lenbuf[2];
    //recv (sockfd, lenbuf, 2, MSG_WAITALL);
    //int resp_len = (lenbuf[0] << 8) | lenbuf[1];
    //unsigned char resp[MAX_MSG_LEN];
    //recv (sockfd, resp, resp_len, MSG_WAITALL);

    resp = send_and_receive_iso(sockfd, msg, msglen, &resposta, resplen);

    print_hex_ascii(resposta, resp);
    
    close(sockfd);
    return 0;
}


