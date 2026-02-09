#include "ipv4.h"
#include "interface.h"
#include "icmp.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

/**
 * Calcula el checksum de Internet (RFC 1071) para la cabecera IP.
 * Se utiliza para verificar la integridad de la cabecera en la recepción.
 */
uint16_t ipv4_checksum(void *vdata, size_t length) {
    uint32_t sum = 0;
    uint16_t *data = vdata;
    
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length > 0) {
        sum += *(uint8_t *)data;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

/**
 * Encapsula un payload en un paquete IPv4 y lo envía a través de la NIC.
 */
void ipv4_send(nic_device_t *nic, uint32_t dst_ip, uint8_t protocol, const void *payload, uint16_t payload_len) {
    unsigned char buffer[2048];
    struct ipv4_header *ip_hdr = (struct ipv4_header *)buffer;
    
    // 1. Construir la cabecera IP
    ip_hdr->version_ihl = (4 << 4) | 5; // Versión 4, IHL 5 (20 bytes)
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = htons(sizeof(struct ipv4_header) + payload_len);
    ip_hdr->identification = htons(0); 
    ip_hdr->flags_fragment_offset = 0; // Sin fragmentación
    ip_hdr->time_to_live = 64;         // TTL estándar
    ip_hdr->protocol = protocol;       // 1 para ICMP, 6 para TCP, etc.

    // Direcciones IP (ya deben estar en network byte order)
    ip_hdr->source_address = nic->ip_address;
    ip_hdr->destination_address = dst_ip;

    // Calcular el checksum de la cabecera
    ip_hdr->header_checksum = 0;
    ip_hdr->header_checksum = ipv4_checksum(ip_hdr, sizeof(struct ipv4_header));

    // 2. Copiar el payload inmediatamente después de la cabecera
    memcpy(buffer + sizeof(struct ipv4_header), payload, payload_len);

    // 3. Preparar la trama Ethernet para el envío físico
    unsigned char ethernet_buffer[2048];
    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    nic_driver_t *drv = nic_get_driver();
    
    // Montaje de la trama Ethernet (Capa 2)
    memcpy(ethernet_buffer, broadcast_mac, 6);         // Destino (Broadcast por simplicidad)
    memcpy(ethernet_buffer + 6, nic->mac_address, 6);  // Origen
    uint16_t etype = htons(0x0800);                    // Ethertype: IPv4
    memcpy(ethernet_buffer + 12, &etype, 2);
    
    // Copiar el paquete IP al payload de Ethernet
    uint16_t ip_packet_len = sizeof(struct ipv4_header) + payload_len;
    memcpy(ethernet_buffer + 14, buffer, ip_packet_len);

    // Envío a través del driver de la NIC
    drv->send_packet(nic, ethernet_buffer, ip_packet_len + 14);
}

/**
 * Procesa un paquete IPv4 entrante recibido desde la capa Ethernet.
 */
void ipv4_receive(nic_device_t *nic, const void *packet, unsigned int len) {
    struct ipv4_header *hdr = (struct ipv4_header *)packet;

    // 1. Validar integridad de la cabecera
    if (ipv4_checksum(hdr, sizeof(struct ipv4_header)) != 0) {
        return; 
    }

    // 2. Filtrar por dirección IP (Unicast a nuestra IP o Broadcast limitado)
    if (hdr->destination_address != nic->ip_address && hdr->destination_address != 0xFFFFFFFF) {
        return; 
    }

    // 3. Calcular ubicación y tamaño del payload IP
    uint16_t ip_hdr_len = (hdr->version_ihl & 0x0F) * 4;
    unsigned char *payload = (unsigned char *)packet + ip_hdr_len;
    uint16_t payload_len = ntohs(hdr->total_length) - ip_hdr_len;

    // 4. Multiplexación: Derivar según el protocolo de la capa de transporte
    if (hdr->protocol == 1) { 
        // Protocolo ICMP
        icmp_receive(nic, hdr->source_address, payload, payload_len);
    } else {
        // Otros protocolos (TCP/UDP/Experimental)
        struct in_addr src_addr;
        src_addr.s_addr = hdr->source_address;

        printf("[IP] Paquete recibido de: %s\n", inet_ntoa(src_addr));
        printf("   | Protocolo: %u | Longitud Datos: %u\n", hdr->protocol, payload_len);
        
        if (payload_len > 0) {
            printf("   | Contenido (Hex): ");
            for(int i = 0; i < (payload_len > 16 ? 16 : payload_len); i++) {
                printf("%02x ", payload[i]);
            }
            printf("\n");
        }
    }
}