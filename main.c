#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "interface.h"
#include "ipv4.h"

// Definimos la estructura Ethernet para poder acceder al ethertype y al payload
struct ethernet_frame {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
    unsigned char payload[1500]; 
} __attribute__((packed));

// Variable global para que el callback pueda acceder a la IP de la NIC
nic_device_t nic;

// CALLBACK DE RECEPCIÓN
// Esta función se activa cada vez que llega CUALQUIER paquete a la tarjeta
void received_packet(const void *data, unsigned int length) {
    struct ethernet_frame *eth = (struct ethernet_frame *)data;
    uint16_t type = ntohs(eth->ethertype);

    // Si es un paquete IPv4 (0x0800), se lo pasamos a la capa de red
    if (type == 0x0800) {
        // Pasamos el puntero al payload (donde empieza la cabecera IP) 
        // y restamos los 14 bytes de la cabecera Ethernet
        ipv4_receive(&nic, eth->payload, length - 14);
    } 
    // Aquí podrías añadir: else if (type == 0x0806) { arp_receive(...); }
}

int main(int argc, char* argv[]) {
    nic_driver_t * drv = nic_get_driver();

    // 1. Inicializar la tarjeta de red (Capa física)
    if (drv->init(&nic) != STATUS_OK) {
        printf("Error: No se pudo inicializar la NIC. ¿Has usado sudo?\n");
        return -1;
    }

    // 2. Configurar la identidad de nuestra interfaz (Capa de Red)
    // Cambia esta IP por la que quieras que tenga tu programa
    nic.ip_address = inet_addr("172.31.200.78");

    // 3. Registrar el callback para que la NIC nos avise al recibir datos
    if (drv->ioctl(&nic, NIC_IOCTL_ADD_RX_CALLBACK, (void *)&received_packet) != STATUS_OK) {
        printf("Error al añadir el callback de recepción\n");
        drv->shutdown(&nic);
        return -1;
    }

    printf("--- STACK INICIALIZADO ---\n");
    printf("Interface: %s\n", nic.name);
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            nic.mac_address[0], nic.mac_address[1], nic.mac_address[2], 
            nic.mac_address[3], nic.mac_address[4], nic.mac_address[5]);
    printf("IP:  %s\n", inet_ntoa(*(struct in_addr *)&nic.ip_address));
    printf("--------------------------\n");

    // 4. PRUEBA DE ENVÍO
    // Vamos a enviar un mensaje "Hola" a una IP de prueba usando nuestra función ipv4_send
    uint32_t ip_destino = inet_addr("172.31.207.255"); // IP de Broadcast o de otro equipo
    char *mensaje = "Mensaje de prueba desde mi propio stack IP";
    
    printf("[TX] Enviando paquete IPv4...\n");
    // Protocolo 253 es para experimentación, payload_len es el tamaño del texto
    ipv4_send(&nic, ip_destino, 253, mensaje, strlen(mensaje) + 1);

    printf("\nEscuchando tráfico IP... Presiona Enter para salir.\n");
    getchar();

    // 5. Cerrar todo correctamente
    drv->shutdown(&nic);
    printf("NIC cerrada. ¡Adiós!\n");

    return 0;
}