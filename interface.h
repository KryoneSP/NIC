#ifndef _NIC_H
#define _NIC_H

#include <stdint.h>
#include <pthread.h>
#include "hal.h"

#define NIC_DEFAULT_MTU                 1500
#define NIC_EXTRA_SIZE                  18  // Ethernet header + CRC 
#define NIC_DEFAULT_MAC                 {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}

#define NIC_IOCTL_CHANGE_MAC            0x01
#define NIC_IOCTL_SET_MTU               0x02
#define NIC_IOCTL_GET_STATS             0x03
#define NIC_IOCTL_RESET_STATS           0x04
#define NIC_IOCTL_ADD_RX_CALLBACK       0x05
#define NIC_IOCTL_ADD_TX_CALLBACK       0x06
#define NIC_IOCTL_ADD_ERROR_CALLBACK    0x07
#define NIC_IOCTL_REMOVE_RX_CALLBACK    0x08
#define NIC_IOCTL_REMOVE_TX_CALLBACK    0x09
#define NIC_IOCTL_REMOVE_ERROR_CALLBACK 0x0A
#define NIC_IOCTL_SET_PROMISCUOUS_MODE  0x0B
#define NIC_IOCTL_UP                    0x0C
#define NIC_IOCTL_DOWN                  0x0D

typedef enum {
    STATUS_OK = 0,
    STATUS_ERROR = -1,
    STATUS_NOT_SUPPORTED = -2,
    STATUS_INVALID_PARAM = -3,
    // Additional status codes can be added here
} status_t;

typedef void (*nic_event_callback_t)(const void *data, unsigned int length);

typedef struct nic_callback {
    nic_event_callback_t callback;
    struct nic_callback *next;
} nic_callback_t;

typedef struct nic_stats {
    unsigned long tx_packets;
    unsigned long rx_packets;
    unsigned long tx_errors;
    unsigned long rx_errors;
    unsigned long collisions;
    // Additional statistics fields can be added here
} nic_stats_t;

typedef struct nic_buffer {
    void *data;
    unsigned int length;
    struct nic_buffer *next;
} nic_buffer_t;

typedef struct nic_device {
    char name[32];
    unsigned char mac_address[6];
    uint32_t ip_address;
    unsigned int mtu;
    unsigned short promiscuous_mode;

    // Callback lists triggered on events
    nic_callback_t *rx_callbacks;
    nic_callback_t *tx_callbacks;
    nic_callback_t *error_callbacks;

    // Statistics
    nic_stats_t stats;

    // Internal buffers for rx and tx
    nic_buffer_t *rx_buffer;
    nic_buffer_t *tx_buffer;

    // Internal hardware device handle
    void *hw_handle;

    // Internal status and thread
    int is_up;
    pthread_t thread;

    // Additional device-specific fields can be added here
    // ...
} nic_device_t;

typedef struct nic_driver {
    status_t (*init)(nic_device_t *device);
    status_t (*shutdown)(nic_device_t *device);
    status_t (*send_packet)(nic_device_t *device, const void *data, unsigned int length);
    status_t (*receive_packet)(nic_device_t *device, void *buffer, unsigned int buffer_length);
    status_t (*ioctl)(nic_device_t *device, unsigned int command, void *arg);
} nic_driver_t;

nic_driver_t * nic_get_driver();
#endif