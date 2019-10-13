#include "packet_interface.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <math.h>
#include <arpa/inet.h>

/* Extra #includes */
/* Your code will be inserted here */

pkt_t* pkt_new()
{
    pkt_t * pkt = (pkt_t *) malloc (sizeof(pkt_t));
    if (pkt == NULL)
        return NULL;
    return pkt;
}

void pkt_del(pkt_t *pkt)
{
    free(pkt->payload);
    free(pkt);
}

pkt_status_code pkt_decode(const char *data, const size_t len, pkt_t *pkt)
{
    if (len<7) { // packet too short
        return E_NOHEADER;
    }
    if (len<11) { // packet too short
        return E_CRC;
    }
    int ret_msg = pkt_set_type(pkt, (uint8_t)(*data) >> 6u); // decode type field
    if(ret_msg != PKT_OK) {
        return ret_msg;
    }

    ret_msg = pkt_set_tr(pkt, (uint8_t)((uint8_t)(*data) << 2u) >> 7u); // decode tr field (crushing type field first)
    if(ret_msg != PKT_OK) {
        return ret_msg;
    }

    ret_msg = pkt_set_window(pkt, (uint8_t)((uint8_t)(*data) << 3u) >> 3u); // decode window field (crushing type & tr fields first)
    if(ret_msg != PKT_OK) {
        return ret_msg;
    }

    size_t nBytes = varuint_len((uint8_t *)data+1); //size of length in bytes

    uint16_t length;
    uint8_t seqnum;
    uint32_t timestamp;
    uint32_t CRC1;

    varuint_decode((uint8_t *)data+1, nBytes, &length);
    seqnum = *(data+1+nBytes);
    timestamp = *((uint32_t *)((uint8_t *)data+2+nBytes));
    memcpy(&CRC1, data+6+nBytes, sizeof(uint32_t)); // length, seqnum & timestamp encoded

    ret_msg = pkt_set_length(pkt, length);
    if(ret_msg != PKT_OK) {
        return ret_msg;
    }

    ret_msg = pkt_set_seqnum(pkt, seqnum);
    if(ret_msg != PKT_OK) {
        return ret_msg;
    }

    ret_msg = pkt_set_timestamp(pkt, timestamp);
    if(ret_msg != PKT_OK) {
        return ret_msg;
    }

    ret_msg = pkt_set_crc1(pkt, ntohl(CRC1));
    if(ret_msg != PKT_OK) {
        return ret_msg;
    }

    //header obtenu a partir du pointeur data
    unsigned char * header;
    header = malloc(6+varuint_predict_len(pkt_get_length(pkt)));
    memcpy(header, data, 6+varuint_predict_len(pkt_get_length(pkt)));
    *header = (uint8_t)(*((uint8_t *)(header))) & ~((uint8_t)(pow(2,5))); // recup of the header to computed CRC

    uint32_t computedCRC1 = crc32(0, Z_NULL, 0);
    computedCRC1 = crc32(computedCRC1, (uint8_t *)header, 6+nBytes);

    if (computedCRC1 != pkt_get_crc1(pkt)) {
        return E_CRC;
    }

    ssize_t header_size = predict_header_length(pkt);
    if(header_size<0) {
        return E_LENGTH;
    }

    size_t expected_size = pkt_get_length(pkt) + header_size + 2*sizeof(uint32_t);
    if (pkt_get_tr(pkt)==0 && expected_size > len) {
        return E_UNCONSISTENT;
    }

    if (pkt_get_tr(pkt)==0 && pkt_get_type(pkt)==1) { // no truncated data type pkt
        size_t payload_size = pkt_get_length(pkt); // size of the payload in bytes

        char * payload = malloc(payload_size);

        int payload_pos = 12;
        if (header_size == 7) {
            payload_pos = 11;
        }

        uint32_t CRC2;
        memcpy(&CRC2, data + payload_pos + payload_size, sizeof(uint32_t));
        pkt_set_crc2(pkt, ntohl(CRC2));

        memcpy(payload, data+payload_pos, payload_size);
        pkt_set_payload(pkt, payload, payload_size); // decode payload
        free(payload);

        uint32_t computedCRC2 = crc32(0L, Z_NULL, 0);

        computedCRC2 = crc32(computedCRC2, (uint8_t *)pkt_get_payload(pkt), payload_size);
        if (computedCRC2 != pkt_get_crc2(pkt)) {
            return E_CRC;
        }

    }

    return PKT_OK;
}

pkt_status_code pkt_encode(const pkt_t* pkt, char *buf, size_t *len)
{
    ssize_t header_size = predict_header_length(pkt);
    if (header_size<0) {
        return E_LENGTH;
    }
    if(*len < pkt_get_length(pkt) + header_size + 2*sizeof(uint32_t)) {
        return E_NOMEM;
    }

    uint8_t first_byte = (pkt_get_type(pkt) << 6u) | (pkt_get_tr(pkt) << 5u) | pkt_get_window(pkt);
    memcpy(buf, &first_byte, 1); // the first byte, composed of the type, tr and length fields

    uint8_t * ptr = (uint8_t *)pkt;
    uint16_t pkt_len = pkt_get_length(pkt); // value of the length field
    ssize_t nBytes = varuint_predict_len(pkt_len); // nBytes the value of the length field in bytes
    if (nBytes == -1)
        return E_LENGTH;


    varuint_encode(pkt_len, (uint8_t *)buf+1, nBytes); // encode length

    memcpy(buf+1+nBytes, ptr+5, 5); // encode Seqnum + timestamp

    uint32_t computedCRC1 = crc32(0L, Z_NULL, 0);
    computedCRC1 = htonl(crc32(computedCRC1, (uint8_t *)buf, 6+nBytes));
    memcpy(buf+6+nBytes, &computedCRC1, 4); // compute & encode CRC1

    memcpy(buf+10+nBytes, pkt_get_payload(pkt), pkt_len); // encode payload

    uint32_t computedCRC2 = crc32(0L, Z_NULL, 0);
    computedCRC2 = crc32(computedCRC2, (uint8_t *)(pkt_get_payload(pkt)), pkt_len);
    computedCRC2 = htonl(computedCRC2);
    memcpy(buf+10+nBytes+pkt_len, &computedCRC2, 4); //compute & encode CRC2

    *len = 14+nBytes+pkt_len;

    return PKT_OK;
}

ptypes_t pkt_get_type  (const pkt_t* pkt)
{
    return pkt->Type;
}

uint8_t  pkt_get_tr(const pkt_t* pkt)
{
    return pkt->TR;
}

uint8_t  pkt_get_window(const pkt_t* pkt)
{
    return pkt->Window;
}

uint8_t  pkt_get_seqnum(const pkt_t* pkt)
{
    return pkt->Seqnum;
}

uint16_t pkt_get_length(const pkt_t* pkt)
{
    return pkt->Length;
}

uint32_t pkt_get_timestamp   (const pkt_t* pkt)
{
    return pkt->Timestamp;
}

uint32_t pkt_get_crc1   (const pkt_t* pkt)
{
    return pkt->CRC1;
}

uint32_t pkt_get_crc2   (const pkt_t* pkt)
{
    return pkt->CRC2;
}

const char * pkt_get_payload(const pkt_t* pkt)
{
    return pkt->payload;
}


pkt_status_code pkt_set_type(pkt_t *pkt, const ptypes_t type)
{
    if (type != PTYPE_DATA && type != PTYPE_ACK && type != PTYPE_NACK) { // type == 0
        return E_TYPE;
    }
    pkt->Type = type;
    return PKT_OK;
}

pkt_status_code pkt_set_tr(pkt_t *pkt, const uint8_t tr)
{
    if (tr != 0 && tr != 1) {
        return E_TR;
    }
    if ((pkt->Type != PTYPE_DATA) && (tr == 1)) // pkt is not a data pkt and is truncated
    {
        return E_TR;
    }
    pkt->TR = tr;
    return PKT_OK;
}

pkt_status_code pkt_set_window(pkt_t *pkt, const uint8_t window)
{
    if (window > 31) {
        return E_WINDOW;
    }
    pkt->Window = window;
    return PKT_OK;
}

pkt_status_code pkt_set_seqnum(pkt_t *pkt, const uint8_t seqnum)
{
    pkt->Seqnum = seqnum;
    return PKT_OK;
}

pkt_status_code pkt_set_length(pkt_t *pkt, const uint16_t length)
{
    if (length > 512) {
        return E_LENGTH;
    }

    ssize_t nBytes = varuint_predict_len(length);
    if (nBytes == -1)
        return E_LENGTH;
    uint16_t tmp;
    if (nBytes == 1) {
        tmp = 0b0111111111111111u & length;
    }
    else { // nBytes == 2
        tmp = 0b1000000000000000u | length;
    }
    pkt->Length = tmp;

    pkt->Length = length;
    return PKT_OK;
}

pkt_status_code pkt_set_timestamp(pkt_t *pkt, const uint32_t timestamp)
{
    pkt->Timestamp = timestamp;
    return PKT_OK;
}

pkt_status_code pkt_set_crc1(pkt_t *pkt, const uint32_t crc1)
{
    pkt->CRC1 = crc1;
    return PKT_OK;
}

pkt_status_code pkt_set_crc2(pkt_t *pkt, const uint32_t crc2)
{
    pkt->CRC2 = crc2;
    return PKT_OK;
}

pkt_status_code pkt_set_payload(pkt_t *pkt, const char *data, const uint16_t length) //aok
{
    if (length > 512) {
        return E_NOMEM;
    }
    pkt->payload = (char *) malloc(length);
    if (pkt->payload == NULL)
        return E_NOMEM;
    memcpy(pkt->payload, data, length);
    pkt_set_length(pkt, length);
    return PKT_OK;
}


ssize_t varuint_decode(const uint8_t *data, const size_t len, uint16_t *retval)
{
    size_t nBytes = varuint_len(data); // nBytes = length field's length in bytes
    if(len < 1 || (nBytes==2 && len==1)) {
        return -1;
    }
    else if (nBytes == 1) {
        *retval = 0b01111111u & *data;
    }
    else { // nBytes == 2
        *retval = 0b0111111111111111u & ntohs(*(uint16_t *)data);
    }
    return nBytes;
}


ssize_t varuint_encode(uint16_t val, uint8_t *data, const size_t len)
{
    ssize_t nBytes = varuint_predict_len(val); // nBytes = length field's length in bytes
    if (len < 1 || nBytes == -1 || (nBytes == 2 && len == 1)) { // len arg too small or error in predict_len or data conflict
        return -1;
    }
    else if (nBytes == 1) {
        uint8_t tmp = 0b01111111u & (uint8_t) val; // making sure L field is set to 0
        *data = tmp;
    }
    else {
        uint16_t tmp = htons(0b1000000000000000u | val); //adding L (on host it is 00000000 10000000) before htons
        memcpy(data, &tmp, sizeof(uint16_t));
    }
    return nBytes;
}

size_t varuint_len(const uint8_t *data) // returns L+1
{
    uint8_t first_bit = (*data) >> 7u;
    return (size_t)(first_bit + 1);
}


ssize_t varuint_predict_len(uint16_t val) // returns 1 or 2 based on length field value, or -1 if an error occurred
{
    if (val >= 0x8000) {
        return -1;
    }
    else if (val < 0x8000 && val >= 0x0080) {
        return 2;
    }
    else {
        return 1;
    }
}


ssize_t predict_header_length(const pkt_t *pkt)
{
    ssize_t size = varuint_predict_len(pkt_get_length(pkt));
    if (size>0) {
        return 6+size;
    }
    else {
        return -1;
    }
}