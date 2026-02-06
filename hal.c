#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "hal.h"

struct device_handle {
    char name[HAL_IFACE_NAMELEN];
    int fd;
    int index;
    unsigned char mac[6];
    unsigned char ip[4];
    unsigned int mtu;
};

void * hal_create_device() {
    struct device_handle *handle = malloc(sizeof(struct device_handle));
    if (!handle) {
       // close(handle->fd);
        return NULL;
    }

    struct ifreq ifr;
    handle->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (handle->fd < 0) {
        free(handle);
        return NULL;
    }
    ifr.ifr_addr.sa_family = AF_PACKET;
    strncpy(ifr.ifr_name, HAL_IFACE_NAME, IFNAMSIZ-1);
    ioctl(handle->fd, SIOCGIFHWADDR, &ifr);
    memcpy(handle->mac, ifr.ifr_hwaddr.sa_data, 6);
    ioctl(handle->fd, SIOCGIFADDR, &ifr);
    memcpy(handle->ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    ioctl(handle->fd, SIOCGIFINDEX, &ifr);
    handle->index = ifr.ifr_ifindex;
    strncpy(handle->name, HAL_IFACE_NAME, HAL_IFACE_NAMELEN-1);
    ioctl(handle->fd, SIOCGIFMTU, &ifr);
    handle->mtu = ifr.ifr_mtu;

    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = handle->index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(handle->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(handle->fd);
        free(handle);
        return NULL;
    }
    return (void*)handle;
}

void hal_remove_device(void *handle) {
    struct device_handle *dev_handle = (struct device_handle *)handle;
    if (dev_handle) {
        close(dev_handle->fd);
        free(dev_handle);
    }
}

unsigned int hal_send(void * handle, void * data, unsigned int length) {
    return write(((struct device_handle *)handle)->fd, data, length);
}

unsigned int hal_receive(void * handle, void * buffer, unsigned int buffer_length) {
    return read(((struct device_handle *)handle)->fd, buffer, buffer_length);
}

void hal_get_mac_address(void * handle, unsigned char *mac) {
    struct device_handle *dev_handle = (struct device_handle *)handle;
    if (dev_handle && mac) {
        memcpy(mac, dev_handle->mac, 6);
    }
}

unsigned int hal_get_mtu(void * handle) {
    struct device_handle *dev_handle = (struct device_handle *)handle;
    if (dev_handle) {
        return dev_handle->mtu;
    }
    return 0;
}