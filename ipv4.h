#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stddef.h>

// Forward declaration para evitar errores de tipo
struct nic_device; 
typedef struct nic_device nic_device_t;

struct ipv4_header {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_address;
    uint32_t destination_address;
} __attribute__((packed));

// Prototipos
uint16_t ipv4_checksum(void *vdata, size_t length);
void ipv4_send(nic_device_t *nic, uint32_t dst_ip, uint8_t protocol, const void *data, uint16_t data_len);
void ipv4_receive(nic_device_t *nic, const void *packet, unsigned int len);

#endif