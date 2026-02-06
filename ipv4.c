#include "ipv4.h"
#include "interface.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

// Función interna para calcular el checksum
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

// Función para preparar el paquete IP
void build_ipv4_packet(struct ipv4_header *ip, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint16_t payload_len) {
    ip->version_ihl = (4 << 4) | 5; // Versión 4, IHL 5 (20 bytes)
    ip->type_of_service = 0;
    // El tamaño total incluye la cabecera IP (20 bytes) + el payload
    ip->total_length = htons(sizeof(struct ipv4_header) + payload_len);
    ip->identification = htons(0x1234); 
    ip->flags_fragment_offset = 0; // No fragmentación
    ip->time_to_live = 64;
    ip->protocol = protocol; // 1 para ICMP, 6 para TCP, 17 para UDP
    ip->source_address = src_ip;      // Debe venir ya en network byte order
    ip->destination_address = dst_ip; // Debe venir ya en network byte order
    
    // Calcular el checksum con el campo de checksum en 0
    ip->header_checksum = 0;
    ip->header_checksum = ipv4_checksum(ip, sizeof(struct ipv4_header));
}

void ipv4_send(nic_device_t *nic, uint32_t dst_ip, uint8_t protocol, const void *payload, uint16_t payload_len) {
    unsigned char buffer [2048];
    struct ipv4_header *ip_hdr = (struct ipv4_header *)buffer;
    
    // 1. Construir la cabecera IP
    ip_hdr->version_ihl = (4 << 4) | 5; // Versión 4, IHL 5 (20 bytes)
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = htons(sizeof(struct ipv4_header) + payload_len);
    ip_hdr->identification = htons(0); 
    ip_hdr->flags_fragment_offset = 0; // No fragmentación
    ip_hdr->time_to_live = 64;
    ip_hdr->protocol = protocol; // 1 para ICMP, 6 para TCP

    // IP de origen y destino (deben venir ya en network byte order)
    ip_hdr->source_address = nic->ip_address; // Usar la IP de la NIC
    ip_hdr->destination_address = dst_ip; // Debe venir ya en network byte order

    // Calcular el checksum
    ip_hdr->header_checksum = 0;
    ip_hdr->header_checksum = ipv4_checksum(ip_hdr, sizeof(struct ipv4_header));

    // 2. Copiar el payload detrás de la cabecera IP
    memcpy(buffer + sizeof(struct ipv4_header), payload, payload_len);

    //3. Enviar el paquete via Ethernet (usando la función de envío de la NIC)
    unsigned char ethernet_buffer[2048];
    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    // Necesitamos acceder al driver de la NIC para enviar el paquete Ethernet
    nic_driver_t *drv = nic_get_driver();
    
    // Montamos la trama ethernet
    memcpy(ethernet_buffer, broadcast_mac, 6); // Destino: Broadcast
    memcpy(ethernet_buffer + 6, nic->mac_address, 6); //
    uint16_t etype = htons(0x0800); // Ethertype para IPv4
    memcpy(ethernet_buffer + 12, &etype, 2);
    memcpy(ethernet_buffer + 14, buffer, sizeof(struct ipv4_header) + payload_len);

    // Enviamos la trama Ethernet
    drv->send_packet(nic, ethernet_buffer, sizeof(struct ipv4_header) + payload_len);
}


void ipv4_receive(nic_device_t *nic, const void *packet, unsigned int len) {
    struct ipv4_header *hdr = (struct ipv4_header *)packet;

    // 1. Validar Checksum
    if (ipv4_checksum(hdr, sizeof(struct ipv4_header)) != 0) {
        return; 
    }

    // 2. Filtrar: ¿Es para nuestra IP o es Broadcast?
    if (hdr->destination_address != nic->ip_address && hdr->destination_address != 0xFFFFFFFF) {
        return; 
    }

    // 3. Extraer el payload (datos tras la cabecera IP)
    uint16_t ip_hdr_len = (hdr->version_ihl & 0x0F) * 4;
    unsigned char *payload = (unsigned char *)packet + ip_hdr_len;
    uint16_t payload_len = ntohs(hdr->total_length) - ip_hdr_len;

    // 4. USAR las variables para imprimir y evitar el warning
    struct in_addr src_addr;
    src_addr.s_addr = hdr->source_address;

    printf("[IP] Paquete recibido de: %s\n", inet_ntoa(src_addr));
    printf("   | Protocolo: %u | Longitud Datos: %u\n", hdr->protocol, payload_len);
    
    if (payload_len > 0) {
        // Imprimimos los primeros bytes como texto para debug
        printf("   | Contenido: %.*s\n", (payload_len > 20 ? 20 : payload_len), (char*)payload);
    }

    /* Aquí es donde conectarás los siguientes protocolos:
       if (hdr->protocol == 1) icmp_receive(nic, payload, payload_len);
       if (hdr->protocol == 6) tcp_receive(nic, payload, payload_len);
    */
}