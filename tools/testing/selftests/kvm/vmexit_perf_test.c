// SPDX-License-Identifier: GPL-2.0-only
/*
 * vmexit_perf_test
 *
 * Copyright (C) 2026, Google LLC.
 *
 * benchmark for various VM-exit types.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define DEFAULT_ITERATIONS 100000

static void guest_code_exit_userspace(uint64_t iterations)
{
	for (uint64_t i = 0; i < iterations; i++) {
		GUEST_SYNC(i);
	}
	GUEST_DONE();
}

#if defined(__x86_64__)
static void guest_code_exit_kernel(uint64_t iterations)
{
	uint64_t start, end;

	start = rdtsc();
	for (uint64_t i = 0; i < iterations; i++)
		asm volatile("cpuid" : : "a"(0) : "rbx", "rcx", "rdx");
	end = rdtsc();

	GUEST_SYNC2(end - start, iterations);
}
#elif defined(__aarch64__)
#include "arm64/arch_timer.h"

static void guest_code_exit_kernel(uint64_t iterations)
{
	uint64_t start, end;

	/* Using the virtual counter to measure cycles/ticks */
	start = timer_get_cntct(VIRTUAL);
	for (uint64_t i = 0; i < iterations; i++)
		asm volatile("mrs x0, id_aa64pfr0_el1" : : : "x0");
	end = timer_get_cntct(VIRTUAL);

	GUEST_SYNC2(end - start, iterations);
}
#endif

static void run_bench_kernel(uint64_t iterations)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	struct timespec host_start, host_end;
	double host_duration;

#if !defined(__x86_64__) && !defined(__aarch64__)
	pr_info("kernel_handled_exit benchmark not implemented for this architecture\n");
	return;
#endif

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_exit_kernel);
	vcpu_args_set(vcpu, 1, iterations);

	clock_gettime(CLOCK_MONOTONIC, &host_start);
	vcpu_run(vcpu);
	clock_gettime(CLOCK_MONOTONIC, &host_end);

	host_duration = (host_end.tv_sec - host_start.tv_sec) + (host_end.tv_nsec - host_start.tv_nsec) / 1e9;

	if (get_ucall(vcpu, &uc) != UCALL_SYNC)
		TEST_FAIL("Unexpected exit reason: %u", vcpu->run->exit_reason);

	uint64_t guest_cycles = uc.args[0];

	printf("%-25s: host %.4fs (%10.4f us/exit), guest %10lu cycles (%10.4f cycles/exit)\n",
	       "kernel_handled_exit", host_duration, (host_duration * 1e6) / iterations,
	       guest_cycles, (double)guest_cycles / iterations);

	kvm_vm_free(vm);
}

static void run_bench_userspace(uint64_t iterations)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct timespec host_start, host_end;
	double host_duration;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_exit_userspace);
	vcpu_args_set(vcpu, 1, iterations);

	clock_gettime(CLOCK_MONOTONIC, &host_start);
	for (uint64_t i = 0; i < iterations; i++) {
		int rc;
		do {
			rc = __vcpu_run(vcpu);
		} while (rc == -1 && errno == EINTR);
		if (vcpu->run->exit_reason == KVM_EXIT_MMIO || vcpu->run->exit_reason == KVM_EXIT_IO) {
			/* Recognized ucall exit, continue to next iteration */
			continue;
		}
		TEST_FAIL("Unexpected exit reason: %u", vcpu->run->exit_reason);
	}
	clock_gettime(CLOCK_MONOTONIC, &host_end);

	host_duration = (host_end.tv_sec - host_start.tv_sec) + (host_end.tv_nsec - host_start.tv_nsec) / 1e9;

	printf("%-25s: host %.4fs (%10.4f us/exit)\n",
	       "userspace_handled_exit", host_duration, (host_duration * 1e6) / iterations);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	uint64_t iterations = DEFAULT_ITERATIONS;
	int opt;
	bool test_kernel = true;
	bool test_userspace = true;

	while ((opt = getopt(argc, argv, "i:ku")) != -1) {
		switch (opt) {
		case 'i':
			iterations = strtoull(optarg, NULL, 10);
			break;
		case 'k':
			test_userspace = false;
			break;
		case 'u':
			test_kernel = false;
			break;
		default:
			fprintf(stderr, "Usage: %s [-i iterations] [-k] [-u]\n", argv[0]);
			fprintf(stderr, "  -k: Only test kernel-handled vmexits\n");
			fprintf(stderr, "  -u: Only test userspace-handled vmexits\n");
			exit(1);
		}
	}

	if (test_kernel)
		run_bench_kernel(iterations);
	if (test_userspace)
		run_bench_userspace(iterations);

	return 0;
}
