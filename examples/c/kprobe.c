// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */


// ********************************* Code Ring Buff - Start **********************************


#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "kprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct sip_msg *sm = data;
    if(sm->flag==1)
	{
		printf("<<<---");
		printf("fd: %d\n",sm->fd);
		printf("Comm: %s\n",sm->comm);
		printf("Buffer Length: %d\n",sm->len);
		printf("%s\n",sm->msg);
		printf("--------------------------------------------------------------------------\n\n");		
	}
	else
	{
		printf("--->>>");
		printf("fd: %d\n",sm->fd);
		printf("Comm: %s\n",sm->comm);
		printf("Buffer Length: %d\n",sm->len);
		printf("%s\n",sm->msg);
		printf("--------------------------------------------------------------------------\n\n");		
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct kprobe_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = kprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!stop) {
		// fprintf(stderr, ".");
		// sleep(1);

		err = ring_buffer__poll(rb, 1 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	
	}

cleanup:
	ring_buffer__free(rb);
	kprobe_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}


// ********************************* Code Ring Buff - End **********************************

// ********************************* Code Perf Buff - Start **********************************


// #include <stdio.h>
// #include <unistd.h>
// #include <signal.h>
// #include <string.h>
// #include <errno.h>
// #include <sys/resource.h>
// #include <bpf/libbpf.h>
// #include "common.h"
// #include "kprobe.skel.h"

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
// {
// 	return vfprintf(stderr, format, args);
// }

// static volatile sig_atomic_t stop;

// static void sig_int(int signo)
// {
// 	stop = 1;
// }

// void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
// {
// 	const struct sip_msg *sm = data;
//     if(sm->flag==1)
// 	{
// 		printf("<<<---");
// 		printf("fd: %d\n",sm->fd);
// 		printf("Comm: %s\n",sm->comm);
// 		printf("Buffer Length: %d\n",sm->len);
// 		printf("%s\n",sm->msg);
// 		printf("---------------------------------------------------------------------------\n\n");		
// 	}
// 	else
// 	{
// 		printf("--->>>");
// 		printf("fd: %d\n",sm->fd);
// 		printf("Comm: %s\n",sm->comm);
// 		printf("Buffer Length: %d\n",sm->len);
// 		printf("%s\n",sm->msg);
// 		printf("---------------------------------------------------------------------------\n\n");		
// 	}
// }

// int main(int argc, char **argv)
// {
// 	struct perf_buffer *pb = NULL;
// 	struct perf_buffer_opts pb_opts = {};
// 	struct kprobe_bpf *skel;

// 	int err;

// 	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
// 	/* Set up libbpf errors and debug info callback */
// 	libbpf_set_print(libbpf_print_fn);

// 	/* Open load and verify BPF application */
// 	skel = kprobe_bpf__open_and_load();
// 	if (!skel) {
// 		fprintf(stderr, "Failed to open BPF skeleton\n");
// 		return 1;
// 	}

// 	/* Attach tracepoint handler */
// 	err = kprobe_bpf__attach(skel);
// 	if (err) {
// 		fprintf(stderr, "Failed to attach BPF skeleton\n");
// 		goto cleanup;
// 	}

// 	pb_opts.sample_cb = handle_event;
// 	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8 /* 32KB per CPU */, &pb_opts);
// 	if (libbpf_get_error(pb)) {
// 		err = -1;
// 		fprintf(stderr, "Failed to create perf buffer\n");
// 		goto cleanup;
// 	}
	

// 	if (signal(SIGINT, sig_int) == SIG_ERR) {
// 		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
// 		goto cleanup;
// 	}

// 	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
// 	       "to see output of the BPF programs.\n");

// 	while (!stop) {
// 		// fprintf(stderr, ".");
// 		// sleep(1);

// 		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
// 		/* Ctrl-C will cause -EINTR */
// 		if (err == -EINTR) {
// 			err = 0;
// 			break;
// 		}
// 		if (err < 0) {
// 			printf("Error polling perf buffer: %d\n", err);
// 			break;
// 		}
	
// 	}

// cleanup:
// 	perf_buffer__free(pb);
// 	kprobe_bpf__destroy(skel);
// 	return err < 0 ? -err : 0;
// }

// ********************************* Code Perf Buff - End **********************************