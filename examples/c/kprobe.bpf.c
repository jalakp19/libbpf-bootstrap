

// ******************* Code from Bootstrap - Start ******************************


// // SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// /* Copyright (c) 2021 Sartura */
// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SEC("kprobe/do_unlinkat")
// int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
// {
// 	// pid_t pid;
// 	// const char *filename;

// 	// pid = bpf_get_current_pid_tgid() >> 32;
// 	// filename = BPF_CORE_READ(name, name);
// 	// bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
// 	return 0;
// }

// SEC("kretprobe/do_unlinkat")
// int BPF_KRETPROBE(do_unlinkat_exit, long ret)
// {
// 	// pid_t pid;

// 	// pid = bpf_get_current_pid_tgid() >> 32;
// 	// bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
// 	return 0;
// }


// ******************* Code from Bootstrap - End ******************************


// ******************* Code using Ring Buff - Start ******************************


// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, int);
	__type(value, struct sip_msg);
} heap SEC(".maps");

SEC("kprobe/__sys_sendto")
int BPF_KPROBE(__sys_sendto)
{
	struct sip_msg *sm;
	
	int zero = 0;
	
	sm = bpf_map_lookup_elem(&heap, &zero);
	if (!sm)
		return 0;

	sm->flag=1;
	sm->fd = (int)(PT_REGS_PARM1(ctx));
	sm->len = (int)(PT_REGS_PARM3(ctx));
	void* buff =(void *)(PT_REGS_PARM2(ctx));

	bpf_get_current_comm(&sm->comm,sizeof(sm->comm));

	if(sm->comm[0]=='s' && sm->comm[1]=='i' && sm->comm[2]=='p' && sm->comm[3]=='p')
	{
		bpf_probe_read_str(&sm->msg, sizeof(sm->msg), (void *)buff);
		bpf_ringbuf_output(&rb, sm, sizeof(*sm), 0);
	}
	return 0;
}

SEC("kprobe/__sys_recvfrom")
int BPF_KPROBE(__sys_recvfrom)
{
	struct sip_msg *sm;
	
	int zero = 0;
	
	sm = bpf_map_lookup_elem(&heap, &zero);
	if (!sm)
		return 0;

	sm->flag=2;
	sm->fd = (int)(PT_REGS_PARM1(ctx));
	sm->len = (int)(PT_REGS_PARM3(ctx));
	void* buff =(void *)(PT_REGS_PARM2(ctx));

	bpf_get_current_comm(&sm->comm,sizeof(sm->comm));

	if(sm->comm[0]=='s' && sm->comm[1]=='i' && sm->comm[2]=='p' && sm->comm[3]=='p')
	{
		bpf_probe_read_str(&sm->msg, sizeof(sm->msg), (void *)buff);
		bpf_ringbuf_output(&rb, sm, sizeof(*sm), 0);
	}
	return 0;
}


// ******************* Code using Ring Buff - End ******************************

// ******************* Code using Perf Buff - Start ******************************

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
// #include "common.h"

// char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// 	__uint(key_size, sizeof(int));
// 	__uint(value_size, sizeof(int));
// } pb SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, 8);
// 	__type(key, int);
// 	__type(value, struct sip_msg);
// } heap SEC(".maps");

// SEC("kprobe/__sys_sendto")
// int BPF_KPROBE(__sys_sendto)
// {
// 	struct sip_msg *sm;
	
// 	int zero = 0;
	
// 	sm = bpf_map_lookup_elem(&heap, &zero);
// 	if (!sm)
// 		return 0;

// 	sm->flag=1;
// 	sm->fd = (int)(PT_REGS_PARM1(ctx));
// 	sm->len = (int)(PT_REGS_PARM3(ctx));
// 	void* buff =(void *)(PT_REGS_PARM2(ctx));

// 	bpf_get_current_comm(&sm->comm,sizeof(sm->comm));

// 	if(sm->comm[0]=='s' && sm->comm[1]=='i' && sm->comm[2]=='p' && sm->comm[3]=='p')
// 	{
// 		bpf_probe_read_str(&sm->msg, sizeof(sm->msg), (void *)buff);
// 		bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, sm, sizeof(*sm));
// 	}
	
// 	return 0;
// }

// SEC("kprobe/__sys_recvfrom")
// int BPF_KPROBE(__sys_recvfrom)
// {
// 	struct sip_msg *sm;
	
// 	int zero = 0;
	
// 	sm = bpf_map_lookup_elem(&heap, &zero);
// 	if (!sm)
// 		return 0;

// 	sm->flag=2;
// 	sm->fd = (int)(PT_REGS_PARM1(ctx));
// 	sm->len = (int)(PT_REGS_PARM3(ctx));
// 	void* buff =(void *)(PT_REGS_PARM2(ctx));

// 	bpf_get_current_comm(&sm->comm,sizeof(sm->comm));

// 	if(sm->comm[0]=='s' && sm->comm[1]=='i' && sm->comm[2]=='p' && sm->comm[3]=='p')
// 	{
// 		bpf_probe_read_str(&sm->msg, sizeof(sm->msg), (void *)buff);
// 		bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, sm, sizeof(*sm));
// 	}
// 	return 0;
// }

// ********************************* Code Perf Buff - End **********************************