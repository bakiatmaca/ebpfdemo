
#ifndef MAIN_BPF_H
#define MAIN_BPF_H

#include "../../include/vmlinux.h"

#include <bpf/bpf_helper_defs.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

struct bpf_map_def {
      unsigned int type;
      unsigned int key_size;
      unsigned int value_size;
      unsigned int max_entries;
      unsigned int map_flags;
};


#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct bpf_map_def SEC("maps") _name = {                        \
        .type = _type,                                              \
        .key_size = sizeof(_key_type),                              \
        .value_size = sizeof(_value_type),                          \
        .max_entries = _max_entries,                                \
    };                                                              

#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240);

#define BPF_PERF_OUTPUT(_name) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024);

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#endif