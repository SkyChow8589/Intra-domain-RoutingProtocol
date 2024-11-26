#include "RoutingProtocolImpl.h"
#include <unordered_set>
#include <list>

RoutingProtocolImpl::RoutingProtocolImpl(Node *n) : RoutingProtocol(n) {
    sys = n;
}

RoutingProtocolImpl::~RoutingProtocolImpl() {

}

void RoutingProtocolImpl::init(unsigned short num_ports, unsigned short router_id, eProtocolType protocol_type) {
    this->num_ports = num_ports;
    this->router_id = router_id;
    this->protocol_type = protocol_type;

    ls_sequence_number = 0;

    for (unsigned short port = 0; port < num_ports; ++port) {
        AlarmData *alarm_data = (AlarmData *) malloc(sizeof(AlarmData));
        alarm_data->type = ALARM_PING;
        alarm_data->port = port;
        sys->set_alarm(this, 0, alarm_data);
    }

    if (protocol_type == P_DV) {
        AlarmData *dv_alarm = (AlarmData *) malloc(sizeof(AlarmData));
        dv_alarm->type = ALARM_DV;
        sys->set_alarm(this, 30000, dv_alarm);
    }

    if (protocol_type == P_LS) {
        AlarmData *ls_alarm = (AlarmData *) malloc(sizeof(AlarmData));
        ls_alarm->type = ALARM_LS;
        sys->set_alarm(this, 30000, ls_alarm);
    }

    AlarmData *timeout_alarm = (AlarmData *) malloc(sizeof(AlarmData));
    timeout_alarm->type = ALARM_TIMEOUT;
    sys->set_alarm(this, 1000, timeout_alarm);
}

void RoutingProtocolImpl::handle_alarm(void *data) {
    AlarmData *alarm_data = (AlarmData *) data;
    switch (alarm_data->type) {
        case ALARM_PING:
            send_ping(alarm_data->port);
            sys->set_alarm(this, 10000, data);
            break;
        case ALARM_DV:
            if (protocol_type == P_DV) {
                send_dv();
                sys->set_alarm(this, 30000, data);
            } else {
                free(data);
            }
            break;
        case ALARM_LS:
            if (protocol_type == P_LS) {
                send_ls_update(false); // false indicates periodic update
                sys->set_alarm(this, 30000, data);
            } else {
                free(data);
            }
            break;
        case ALARM_TIMEOUT:
            check_timeouts();
            sys->set_alarm(this, 1000, data);
            break;
        default:
            free(data);
            break;
    }
}

void RoutingProtocolImpl::recv(unsigned short port, void *packet, unsigned short size) {
    char *pkt = (char *) packet;
    unsigned char packet_type = pkt[0];

    switch (packet_type) {
        case DATA:
            if (port == SPECIAL_PORT) {
                unsigned short net_src_id = htons(router_id);
                memcpy(pkt + 4, &net_src_id, 2);
            }
            forward_data(port, packet, size);
            break;
        case PING:
            handle_ping(port, packet, size);
            break;
        case PONG:
            handle_pong(port, packet, size);
            break;
        case DV:
            if (protocol_type == P_DV) {
                handle_dv(port, packet, size);
            } else {
                free(packet);
            }
            break;
        case LS:
            if (protocol_type == P_LS) {
                handle_ls_update(port, packet, size);
            } else {
                free(packet);
            }
            break;
        default:
            free(packet);
            break;
    }
}

void RoutingProtocolImpl::send_ping(unsigned short port) {
    // Construct PING packet
    const unsigned short header_size = 12;
    const unsigned short payload_size = 4;
    unsigned short packet_size = header_size + payload_size;
    char *packet = (char *) malloc(packet_size);

    // Fill in header
    unsigned char packet_type = PING;
    unsigned char reserved = 0;
    unsigned short size = htons(packet_size);
    unsigned short src_id = htons(router_id);
    unsigned short dest_id = htons(0);

    memcpy(packet, &packet_type, 1);
    memcpy(packet + 1, &reserved, 1);
    memcpy(packet + 2, &size, 2);
    memcpy(packet + 4, &src_id, 2);
    memcpy(packet + 6, &dest_id, 2);
    memset(packet + 8, 0, 4);

    // Fill in payload (timestamp)
    unsigned int timestamp = htonl(sys->time());
    memcpy(packet + header_size, &timestamp, payload_size);

    // Send packet
    sys->send(port, packet, packet_size);
}

void RoutingProtocolImpl::handle_ping(unsigned short port, void *packet, unsigned short size) {
    char *pkt = (char *) packet;

    unsigned short src_id;
    memcpy(&src_id, pkt + 4, 2);
    src_id = ntohs(src_id);

    pkt[0] = PONG;

    unsigned short our_id = htons(router_id);
    memcpy(pkt + 4, &our_id, 2);
    unsigned short dest_id = htons(src_id);
    memcpy(pkt + 6, &dest_id, 2);

    sys->send(port, packet, size);
}

void RoutingProtocolImpl::handle_pong(unsigned short port, void *packet, unsigned short size) {
    char *pkt = (char *) packet;

    unsigned short src_id;
    memcpy(&src_id, pkt + 4, 2);
    src_id = ntohs(src_id);

    unsigned int sent_time;
    memcpy(&sent_time, pkt + 12, 4);
    sent_time = ntohl(sent_time);

    unsigned int current_time = sys->time();
    unsigned int rtt = current_time - sent_time;

    unsigned int old_cost = INFINITY_COST;
    bool neighbor_changed = false;
    bool neighbor_existed = false;

    if (neighbor_map.count(src_id) > 0) {
        neighbor_existed = true;
        old_cost = neighbor_map[src_id].cost;
        if (old_cost != rtt) {
            neighbor_changed = true;
        }
    } else {
        neighbor_changed = true;
    }

    Neighbor neighbor;
    neighbor.neighbor_id = src_id;
    neighbor.port = port;
    neighbor.last_ping_time = current_time;
    neighbor.cost = rtt;

    port_map[port] = neighbor;
    neighbor_map[src_id] = neighbor;

    if (protocol_type == P_DV) {
        bool dv_changed = false;
        if (neighbor_existed) {
            DVEntry dv_entry = distance_vector[src_id];

            if (dv_entry.next_hop == src_id) {

                if (neighbor_changed) {
                    dv_entry.cost = rtt;
                    distance_vector[src_id] = dv_entry;
                    dv_changed = true;
                }
            } else {
                if (distance_vector[src_id].cost == 0 or distance_vector[src_id].cost > rtt) {

                    dv_entry.next_hop = src_id;
                    dv_entry.cost = rtt;
                    distance_vector[src_id] = dv_entry;
                    forwarding_table[src_id] = port;
                    dv_changed = true;
                }
            }
        } else {

            if (distance_vector.count(src_id) == 0 || distance_vector[src_id].cost > rtt) {

                DVEntry dv_entry;
                dv_entry.next_hop = src_id;

                dv_entry.cost = rtt;
                distance_vector[src_id] = dv_entry;
                forwarding_table[src_id] = port;
                dv_changed = true;
            }
        }

        if (dv_changed) {
            send_dv();
        }
    }

    if (protocol_type == P_LS) {
        if (neighbor_changed) {
            send_ls_update(true);
        }
    }

    free(packet);
}


void RoutingProtocolImpl::send_dv() {
    for (auto &neighbor_pair: neighbor_map) {
        unsigned short neighbor_id = neighbor_pair.first;
        Neighbor &neighbor = neighbor_pair.second;
        unsigned short port = neighbor.port;

        const unsigned short header_size = 12;
        std::vector<char> entries;

        for (auto &dv_pair: distance_vector) {
            unsigned short dest_id = dv_pair.first;
            DVEntry &dv_entry = dv_pair.second;

            unsigned short cost = dv_entry.cost;

            if (dv_entry.next_hop == neighbor_id && dest_id != neighbor_id) {
                cost = INFINITY_COST;
            }

            if (dest_id == neighbor_id) {
                continue;
            }

            // Prepare entry
            char entry[4];
            unsigned short net_dest_id = htons(dest_id);
            unsigned short net_cost = htons(cost);
            memcpy(entry, &net_dest_id, 2);
            memcpy(entry + 2, &net_cost, 2);

            entries.insert(entries.end(), entry, entry + 4);
        }

        // Packet size
        unsigned short packet_size = header_size + entries.size();
        char *packet = (char *) malloc(packet_size);

        // Fill in header
        unsigned char packet_type = DV;
        unsigned char reserved = 0;
        unsigned short net_size = htons(packet_size);
        unsigned short net_src_id = htons(router_id);
        unsigned short net_dest_id = htons(neighbor_id);

        memcpy(packet, &packet_type, 1);
        memcpy(packet + 1, &reserved, 1);
        memcpy(packet + 2, &net_size, 2);
        memcpy(packet + 4, &net_src_id, 2);
        memcpy(packet + 6, &net_dest_id, 2);
        memset(packet + 8, 0, 4);

        // Copy entries into packet
        if (!entries.empty()) {
            memcpy(packet + header_size, entries.data(), entries.size());
        }

        sys->send(port, packet, packet_size);
    }
}

void RoutingProtocolImpl::handle_dv(unsigned short port, void *packet, unsigned short size) {
    char *pkt = (char *) packet;
    unsigned short header_size = 12;

    unsigned short src_id;
    memcpy(&src_id, pkt + 4, 2);
    src_id = ntohs(src_id);

    if (neighbor_map.count(src_id) == 0) {
        free(packet);
        return;
    }

    neighbor_map[src_id].last_ping_time = sys->time();
    port_map[port].last_ping_time = sys->time();

    unsigned short num_entries = (size - header_size) / 4;
    char *entry_ptr = pkt + header_size;


    for (unsigned short i = 0; i < num_entries; ++i) {
        unsigned short dest_id;
        unsigned short cost;

        memcpy(&dest_id, entry_ptr, 2);
        dest_id = ntohs(dest_id);

        memcpy(&cost, entry_ptr + 2, 2);
        cost = ntohs(cost);

        entry_ptr += 4;

        if (distance_vector.count(dest_id) == 0) {

            if (cost == INFINITY_COST || dest_id == router_id) {

                continue;
            }

            DVEntry new_entry;
            new_entry.next_hop = src_id;

            new_entry.cost = cost + neighbor_map[src_id].cost;

            distance_vector[dest_id] = new_entry;

            forwarding_table[dest_id] = port;

            send_dv();
        } else {
            if (cost == INFINITY_COST) {

                unsigned short current_next_hop = distance_vector[dest_id].next_hop;

                if (current_next_hop != src_id) {

                    continue;
                }

                distance_vector[dest_id].cost = INFINITY_COST;
                distance_vector[dest_id].next_hop = -1;
                forwarding_table.erase(dest_id);


                send_dv();

                distance_vector.erase(dest_id);


            } else {

                if (cost + neighbor_map[src_id].cost < distance_vector[dest_id].cost) {
                    distance_vector[dest_id].cost = cost + neighbor_map[src_id].cost;
                    distance_vector[dest_id].next_hop = src_id;

                    forwarding_table[dest_id] = port;
                    send_dv();
                }
            }
        }
    }

    free(packet);
}

void RoutingProtocolImpl::send_ls_update(bool isTriggered) {
    ls_sequence_number++;

    LSAdvertisement ls_ad;
    ls_ad.sequence_number = ls_sequence_number;
    ls_ad.last_updated_time = sys->time();

    for (auto &neighbor_pair: neighbor_map) {
        unsigned int neighbor_id = neighbor_pair.first;
        unsigned int cost = neighbor_pair.second.cost;
        ls_ad.neighbors[neighbor_id] = cost;
    }

    link_state_database[router_id] = ls_ad;

    // Construct LS packet
    const unsigned short header_size = 16; // Based on the packet format

    unsigned short num_entries = neighbor_map.size();
    unsigned short packet_size = header_size + num_entries * 8;

    char *packet = (char *) malloc(packet_size);

    unsigned char packet_type = LS;
    unsigned char reserved = 0;
    unsigned short net_size = htons(packet_size);
    unsigned int net_src_id = htonl(router_id);
    unsigned int ignored = 0; // Ignored field
    unsigned int net_sequence_number = htonl(ls_sequence_number);

    memcpy(packet, &packet_type, 1);
    memcpy(packet + 1, &reserved, 1);
    memcpy(packet + 2, &net_size, 2);
    memcpy(packet + 4, &net_src_id, 4);
    memcpy(packet + 8, &ignored, 4);
    memcpy(packet + 12, &net_sequence_number, 4);

    // Fill in neighbor entries
    char *entry_ptr = packet + header_size;

    for (auto &neighbor_pair: neighbor_map) {
        unsigned int neighbor_id = neighbor_pair.first;
        unsigned int cost = neighbor_pair.second.cost;

        unsigned int net_neighbor_id = htonl(neighbor_id);
        unsigned int net_cost = htonl(cost);

        memcpy(entry_ptr, &net_neighbor_id, 4);
        memcpy(entry_ptr + 4, &net_cost, 4);

        entry_ptr += 8;
    }

    // Flood the packet to all port_map
    for (auto &neighbor_pair: neighbor_map) {
        unsigned short port = neighbor_pair.second.port;
        char *packet_copy = (char *) malloc(packet_size);
        memcpy(packet_copy, packet, packet_size);

        sys->send(port, packet_copy, packet_size);
    }

    free(packet);

    // Recompute shortest paths after sending LS update
    recompute_shortest_paths();
}


void RoutingProtocolImpl::recompute_shortest_paths() {
    std::unordered_map<unsigned short, std::unordered_map<unsigned short, unsigned int>> graph;

    LSAdvertisement &our_ls_ad = link_state_database[router_id];
    for (auto &neighbor: our_ls_ad.neighbors) {
        unsigned short neighbor_id = neighbor.first;
        unsigned int cost = neighbor.second;
        graph[router_id][neighbor_id] = cost;
        graph[neighbor_id][router_id] = cost;
    }

    for (auto &ls_entry: link_state_database) {
        unsigned short node_id = ls_entry.first;
        if (node_id == router_id) continue;

        LSAdvertisement &ls_ad = ls_entry.second;

        for (auto &neighbor: ls_ad.neighbors) {
            unsigned short neighbor_id = neighbor.first;
            unsigned int cost = neighbor.second;

            graph[node_id][neighbor_id] = cost;
            graph[neighbor_id][node_id] = cost;
        }
    }

    std::unordered_map<unsigned short, unsigned int> dist;
    std::unordered_map<unsigned short, unsigned short> prev;
    std::unordered_map<unsigned short, bool> visited;

    for (auto &node_entry: graph) {
        unsigned short node_id = node_entry.first;
        dist[node_id] = (node_id == router_id) ? 0 : INFINITY_COST;
        visited[node_id] = false;
    }

    for (size_t i = 0; i < dist.size(); ++i) {
        // Find the unvisited node with the smallest distance
        unsigned int min_dist = INFINITY_COST;
        unsigned short min_node = 0;

        for (auto &entry: dist) {
            unsigned short node_id = entry.first;
            if (!visited[node_id] && entry.second <= min_dist) {
                min_dist = entry.second;
                min_node = node_id;
            }
        }

        if (min_dist == INFINITY_COST) {
            break; // Remaining nodes are unreachable
        }

        visited[min_node] = true;

        // Update distances to port_map
        if (graph.count(min_node) > 0) {
            for (auto &neighbor_entry: graph[min_node]) {
                unsigned short neighbor_id = neighbor_entry.first;
                unsigned int cost = neighbor_entry.second;

                if (!visited[neighbor_id]) {
                    unsigned int new_dist = dist[min_node] + cost;
                    if (new_dist < dist[neighbor_id]) {
                        dist[neighbor_id] = new_dist;
                        prev[neighbor_id] = min_node;
                    }
                }
            }
        }
    }

    // Update the forwarding table
    forwarding_table.clear();

    for (auto &entry: dist) {
        unsigned short dest_id = entry.first;

        if (dest_id == router_id) {
            continue;
        }

        if (dist[dest_id] == INFINITY_COST) {
            continue;
        }

        // Find the next hop
        unsigned short next_hop = dest_id;
        unsigned short prev_node = prev[dest_id];

        while (prev_node != router_id) {
            next_hop = prev_node;
            prev_node = prev[next_hop];
        }

        // Get the port corresponding to the next hop
        if (neighbor_map.count(next_hop) > 0) {
            unsigned short out_port = neighbor_map[next_hop].port;
            forwarding_table[dest_id] = out_port;
        }
    }
}


void RoutingProtocolImpl::forward_data(unsigned short port, void *packet, unsigned short size) {
    char *pkt = (char *) packet;

    unsigned short dest_id;
    memcpy(&dest_id, pkt + 6, 2);
    dest_id = ntohs(dest_id);

    if (dest_id == router_id) {
        free(packet);
        return;
    }

    if (forwarding_table.count(dest_id) > 0) {
        unsigned short out_port = forwarding_table[dest_id];

        if (out_port < num_ports) {
            sys->send(out_port, packet, size);
        } else {
            free(packet);
        }
    } else {
        free(packet);
    }
}


void RoutingProtocolImpl::check_timeouts() {
    unsigned int current_time = sys->time();

    std::list<int> delete_id;

    for (auto it = port_map.begin(); it != port_map.end();) {
        Neighbor &neighbor = it->second;
        if (current_time - neighbor.last_ping_time > 15000) {
            unsigned short neighbor_id = neighbor.neighbor_id;

            if (protocol_type == P_DV) {
                for (auto dv_it = distance_vector.begin(); dv_it != distance_vector.end();) {
                    DVEntry &dv_entry = dv_it->second;
                    if (dv_entry.next_hop == neighbor_id) {
                        unsigned short dest_id = dv_it->first;
                        forwarding_table.erase(dest_id);

                        distance_vector[dest_id].cost = INFINITY_COST;
                        distance_vector[dest_id].next_hop = -1;  // 设置无效的下一跳


                        delete_id.push_back(dest_id);
                    }
                    ++dv_it;
                }
            }

            it = port_map.erase(it);
            neighbor_map.erase(neighbor_id);

            if (protocol_type == P_LS) {
                send_ls_update(true);
            }
        } else {
            ++it;
        }
    }

    if (protocol_type == P_DV && !delete_id.empty()) {
        send_dv();
        for (int id: delete_id) {
            distance_vector.erase(id);
        }
    }

    if (protocol_type == P_LS) {
        bool need_recompute = false;

        // 移除过期的 LS 条目
        for (auto it = link_state_database.begin(); it != link_state_database.end();) {
            unsigned int last_updated = it->second.last_updated_time;
            if (current_time - last_updated > 45000) {
                unsigned short node_id = it->first;
                it = link_state_database.erase(it);

                if (node_id == router_id) {
                    send_ls_update(true);
                } else {
                    need_recompute = true;
                }
            } else {
                ++it;
            }
        }

        if (need_recompute) {
            recompute_shortest_paths();
        }
    }
}

void RoutingProtocolImpl::handle_ls_update(unsigned short port, void *packet, unsigned short size) {
    char *pkt = (char *) packet;

    // Parse the header
    //unsigned char packet_type = pkt[0];
    //unsigned char reserved = pkt[1];
    unsigned short net_size;
    memcpy(&net_size, pkt + 2, 2);
    unsigned int net_src_id;
    memcpy(&net_src_id, pkt + 4, 4);
    unsigned int ignored;
    memcpy(&ignored, pkt + 8, 4);
    unsigned int net_sequence_number;
    memcpy(&net_sequence_number, pkt + 12, 4);

    unsigned short pkt_size = ntohs(net_size);
    unsigned int src_id = ntohl(net_src_id);
    unsigned int sequence_number = ntohl(net_sequence_number);

    // Check if we have seen this sequence number from this source before
    bool is_newer = false;

    if (link_state_database.count(src_id) == 0) {
        is_newer = true;
    } else if (sequence_number > link_state_database[src_id].sequence_number) {
        is_newer = true;
    }

    if (is_newer) {
        // Update the link_state_database
        LSAdvertisement ls_ad;
        ls_ad.sequence_number = sequence_number;
        ls_ad.last_updated_time = sys->time();

        // Parse the neighbor entries
        unsigned short num_entries = (pkt_size - 16) / 8;
        char *entry_ptr = pkt + 16;

        for (unsigned short i = 0; i < num_entries; ++i) {
            unsigned int net_neighbor_id;
            memcpy(&net_neighbor_id, entry_ptr, 4);
            unsigned int neighbor_id = ntohl(net_neighbor_id);

            unsigned int net_cost;
            memcpy(&net_cost, entry_ptr + 4, 4);
            unsigned int cost = ntohl(net_cost);

            ls_ad.neighbors[neighbor_id] = cost;

            entry_ptr += 8;
        }

        link_state_database[src_id] = ls_ad;

        // Run Dijkstra's algorithm to recompute shortest paths
        recompute_shortest_paths();

        // Flood the packet to all port_map except the one we received it from
        for (auto &neighbor_pair: neighbor_map) {
            unsigned short neighbor_port = neighbor_pair.second.port;

            if (neighbor_port != port) {
                char *packet_copy = (char *) malloc(size);
                memcpy(packet_copy, packet, size);

                sys->send(neighbor_port, packet_copy, size);
            }
        }
    } else {
        // If the sequence number is the same, update the last_updated_time
        if (link_state_database.count(src_id) > 0 && sequence_number == link_state_database[src_id].sequence_number) {
            link_state_database[src_id].last_updated_time = sys->time();
        }
    }

    // Else, we discard the packet
    free(packet);
}
