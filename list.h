
#pragma once
#ifndef NG_LIST_H
#define NG_LIST_H

struct list_n {
        struct list_n *prev;
        struct list_n *next;
        void *v;
};

struct list {
        struct list_n *head;
        struct list_n *tail;
};

void init_global_lists();

void *list_head(struct list *l);
void *list_tail(struct list *l);

struct list_n *list_prepend(struct list *l, void *v);
struct list_n *list_append(struct list *l, void *v);

void *list_pop_front(struct list *l);
void *list_pop_back(struct list *l);

void list_remove_node(struct list *l, struct list_n *node);
void list_remove(struct list *l, void *v);

void list_free(struct list *l);

void list_foreach(struct list *l, void (*fn)(void *));

#endif // NG_LIST_H
