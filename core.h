#pragma once
#ifndef IPSTACK_CORE_H
#define IPSTACK_CORE_H

#include "list.h"

struct net_if;

struct pkb {
    struct net_if *from;
    list_node queue;
    int refcount;

    uint8_t user_anno[32];

    int length; // -1 if unknown
    char buffer[];
};

struct pkb *new_pk();
struct pkb *new_pk_len(size_t len);
void pk_incref(struct pkb *pk);
void pk_decref(struct pkb *pk);
void free_pk(struct pkb *pk);

#endif // IPSTACK_CORE_H
