#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <string.h>
#include "packet_interface.h"


int main() {
    pkt_t * test_pkt = malloc(18 + sizeof(char *));
    size_t len = 400;
    pkt_set_type(test_pkt, 1);
    pkt_set_tr(test_pkt, 0);
    pkt_set_window(test_pkt, 16);
    pkt_set_length(test_pkt, len);
    pkt_set_seqnum(test_pkt, 3);
    pkt_set_timestamp(test_pkt, 4);
    char str[len];
    int i;
    for (i=0; i<len-1; i++) {
        str[i]='1';
    }
    str[len]='\0';
    pkt_set_payload(test_pkt, str, len);


    pkt_set_crc1(test_pkt, 0);
    pkt_set_crc2(test_pkt, 0);

    size_t size = 16 + len;
    unsigned char encoded_pkt[size];
    int status = pkt_encode(test_pkt, (char *) encoded_pkt, &size);
    if (status != PKT_OK) {
        printf("Error at encode, status : %d\n", status);
    }

    pkt_t * decoded_pkt = malloc (18 + sizeof(char *));//18+8
    status = pkt_decode(encoded_pkt, size, decoded_pkt);
    if (status != PKT_OK) {
        printf("\nError, status at decode : %d\n", status);
    }

    printf("Hello World\n");
}