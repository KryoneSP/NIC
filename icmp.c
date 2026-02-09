#include "icmp.h"
#include "ipv4.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

// Checksum estándar de Internet (RFC 1071)
static uint16_t icmp_calculate_checksum(void *vdata, size_t length) {
    uint32_t sum = 0;
    uint16_t *data = vdata;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length > 0) sum += *(uint8_t *)data;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

// --- FUNCIÓN DE ENVÍO ---
void icmp_send(void *nic, uint32_t dst_ip, uint8_t type, uint8_t code, uint16_t id, uint16_t seq, const void *data, uint16_t data_len) {
    nic_device_t *nic_dev = (nic_device_t *)nic;
    uint16_t total_len = sizeof(icmp_hdr_t) + data_len;
    uint8_t buffer[total_len];

    icmp_hdr_t *icmp = (icmp_hdr_t *)buffer;
    icmp->type = type;
    icmp->code = code;
    icmp->checksum = 0;
    icmp->id = htons(id);  // Importante: Orden de red (Big Endian)
    icmp->seq = htons(seq);

    // Si el ping lleva datos (payload), los copiamos después de la cabecera
    if (data && data_len > 0) {
        memcpy(buffer + sizeof(icmp_hdr_t), data, data_len);
    }

    // Calculamos el checksum sobre la cabecera + los datos
    icmp->checksum = icmp_calculate_checksum(buffer, total_len);

    // Bajamos a la capa de red (IPv4). El protocolo 1 es ICMP.
    ipv4_send(nic_dev, dst_ip, 1, buffer, total_len);
}

// --- FUNCIÓN DE RECEPCIÓN ---
void icmp_receive(void *nic, uint32_t src_ip, const void *payload, uint16_t len) {
    if (len < sizeof(icmp_hdr_t)) return;

    icmp_hdr_t *request = (icmp_hdr_t *)payload;

    if (request->type == ICMP_TYPE_ECHO_REQUEST) {
        // Log para depuración
        struct in_addr addr;
        addr.s_addr = src_ip;
        printf("[ICMP] Echo Request recibido de %s. Respondiendo...\n", inet_ntoa(addr));

        // Extraemos el payload que venía en el request para devolverlo (comportamiento estándar)
        const void *incoming_data = (uint8_t *)payload + sizeof(icmp_hdr_t);
        uint16_t incoming_data_len = len - sizeof(icmp_hdr_t);

        // RESPONDEMOS llamando a icmp_send de forma independiente
        icmp_send(nic, 
                  src_ip, 
                  ICMP_TYPE_ECHO_REPLY, 
                  0, 
                  ntohs(request->id), 
                  ntohs(request->seq), 
                  incoming_data, 
                  incoming_data_len);
    } 
    else if (request->type == ICMP_TYPE_ECHO_REPLY) {
        printf("[ICMP] Echo Reply recibido de un host remoto.\n");
    }
}