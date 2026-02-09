#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include "hal.h" // O donde tengas definido nic_device_t o similar

#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_ECHO_REQUEST 8

// Definición manual y limpia
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;      // Ahora sí se llama id
    uint16_t seq;     // Ahora sí se llama seq
} __attribute__((packed)) icmp_hdr_t;

void icmp_receive(void *nic, uint32_t src_ip, const void *payload, uint16_t len);
void icmp_send(void *nic, uint32_t dst_ip, uint8_t type, uint8_t code, uint16_t id, uint16_t seq, const void *data, uint16_t data_len);

#endif