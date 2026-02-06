#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "interface.h"

void received_packet(const void *data, unsigned int length) {
    printf("Received packet of length %u [", length);
    const unsigned char *bytes = (const unsigned char *)data;
    for (unsigned int i = 0; i < length && i < 10; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("]\n");
}

struct ethernet_frame {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
    unsigned char payload[1500]; //Hardcoded mtu for testing!!!
} __attribute__((packed));

unsigned int test_ethernet(unsigned char * buffer, const unsigned char *src, const unsigned char *dst, unsigned short ethertype, const unsigned char *payload, unsigned int payload_length) {
    struct ethernet_frame *frame = (struct ethernet_frame *)buffer;
    for (int i = 0; i < 6; i++) {
        frame->dest_mac[i] = dst[i];
    }
    for (int i = 0; i < 6; i++) {
        frame->src_mac[i] = src[i];
    }
    frame->ethertype = htons(ethertype);
    memcpy(frame->payload, payload, payload_length);
    return sizeof(struct ethernet_frame) - 1500 + payload_length; //Hardcoded mtu for testing!!!
}

int main(int argc, char* argv[]) {
    nic_device_t nic;
    nic_driver_t * drv = nic_get_driver();

    if (drv->init(&nic) != STATUS_OK) {
        printf("Failed to initialize NIC\n");
        return -1;
    }
    if (drv->ioctl(&nic, NIC_IOCTL_ADD_RX_CALLBACK, (void *)&received_packet) != STATUS_OK) {
        printf("Failed to add RX callback\n");
        drv->shutdown(&nic);
        return -1;
    }

    unsigned char buffer[2048];
    unsigned int packet_length = test_ethernet(
        buffer,
        nic.mac_address, // Source MAC
        (unsigned char[]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // Broadcast MAC
        0x9000, // Ethertype for testing
        (unsigned char *)"Hello, this is a test payload", //Payload content
        29 // Payload length
    );
    
    if (drv->send_packet(&nic, buffer, packet_length) != STATUS_OK) {
        printf("Failed to send packet\n");
        drv->shutdown(&nic);
        return -1;
    }

    //Wait for key press to exit
    printf("Press Enter to exit...\n");
    getchar();

    if (drv->shutdown(&nic) != STATUS_OK) {
        printf("Failed to shutdown NIC\n");
        return -1;
    }
    return 0;
}