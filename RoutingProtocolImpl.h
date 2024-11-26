#ifndef ROUTINGPROTOCOLIMPL_H
#define ROUTINGPROTOCOLIMPL_H

#include "RoutingProtocol.h"
#include "Node.h"
#include <unordered_map>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>

class RoutingProtocolImpl : public RoutingProtocol {
public:
    RoutingProtocolImpl(Node *n);

    ~RoutingProtocolImpl();

    void init(unsigned short num_ports, unsigned short router_id, eProtocolType protocol_type);

    void handle_alarm(void *data);

    void recv(unsigned short port, void *packet, unsigned short size);

private:
    Node *sys;

    struct Neighbor {
        unsigned short neighbor_id;
        unsigned short port;
        unsigned int last_ping_time;
        unsigned int cost;
    };


    struct DVEntry {
        unsigned short next_hop;
        unsigned short cost;
    };

    struct LSAdvertisement {
        unsigned int sequence_number;
        unsigned int last_updated_time;
        std::unordered_map<unsigned short, unsigned int> neighbors;
    };

    std::unordered_map<unsigned short, Neighbor> port_map;

    std::unordered_map<unsigned short, Neighbor> neighbor_map;

    std::unordered_map<unsigned short, DVEntry> distance_vector;

    std::unordered_map<unsigned short, unsigned short> forwarding_table;

    std::unordered_map<unsigned short, LSAdvertisement> link_state_database;

    unsigned int ls_sequence_number;

    unsigned short num_ports;
    unsigned short router_id;
    eProtocolType protocol_type;

    enum AlarmType {
        ALARM_PING,
        ALARM_DV,
        ALARM_LS,
        ALARM_TIMEOUT
    };

    struct AlarmData {
        AlarmType type;
        unsigned short port;
    };

    void send_ping(unsigned short port);

    void send_dv();

    void send_ls_update(bool isTriggered);

    void check_timeouts();

    void handle_ping(unsigned short port, void *packet, unsigned short size);

    void handle_pong(unsigned short port, void *packet, unsigned short size);

    void handle_dv(unsigned short port, void *packet, unsigned short size);

    void handle_ls_update(unsigned short port, void *packet, unsigned short size);

    void forward_data(unsigned short port, void *packet, unsigned short size);

    bool update_distance_vector();

    void recompute_shortest_paths();
};

#endif
