/*
 * Copyright 2018 Xaptum, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#ifndef ENFTUN_LIST_H
#define ENFTUN_LIST_H

struct enftun_list
{
    struct enftun_list *next, *prev;
};

static inline
int
enftun_list_init(struct enftun_list* head)
{
    head->next = head->prev = head;
}

static inline
int
enftun_list_empty(struct enftun_list* head)
{
    return head->next == head;
}

static inline
void
enftun_list_append(struct enftun_list* head, struct enftun_list* new)
{
    new->next       = head;
    new->prev       = head->prev;
    new->prev->next = new;
    head->prev      = new;
}

static inline
void
enftun_list_delete(struct enftun_list* entry)
{
    entry->next->prev = entry->prev;
    entry->prev->next = entry->next;
}

#endif // ENFTUN_LIST_H
