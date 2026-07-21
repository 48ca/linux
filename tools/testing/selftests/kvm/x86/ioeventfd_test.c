// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"

struct guest_vals {
	int i;
	unsigned short port;
	char data;
};

static struct guest_vals vals;

static void guest_code_pio(void)
{
	int i;
	for (i = 0; i < vals.i; i++)
		asm volatile("outb %b0, %1" :: "a"(vals.data), "d"(vals.port));

	GUEST_DONE();
}

void test_pio_ioeventfd_basic(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct ucall uc;
	struct kvm_ioeventfd ioeventfd;
	int i;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_pio);
	run = vcpu->run;

	memset(&ioeventfd, 0, sizeof(ioeventfd));
	ioeventfd.addr = 0x80;
	ioeventfd.flags = KVM_IOEVENTFD_FLAG_PIO;
	ioeventfd.fd = eventfd(0, 0);
	vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);

	vals.i = 10;
	vals.port = 0x80;
	vals.data = 1;
	sync_global_to_guest(vcpu->vm, vals);
	i = 0;
	while (1) {
		printf("vcpu_run %d\n", i++);
		vcpu_run(vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
		eventfd_t val;
		eventfd_read(ioeventfd.fd, &val);
		TEST_ASSERT(val == vals.i, "Expected %d exits, got %ld\n", vals.i, val);

		if (get_ucall(vcpu, &uc))
			break;

		TEST_ASSERT(run->io.port == 0x80,
			    "Expected I/O at port 0x80, got port 0x%x", run->io.port);
	}
	switch (uc.cmd) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unknown ucall %lu", uc.cmd);
	}

	/* After deassignment, every PIO should cause an exit. */
	ioeventfd.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
	vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	close(ioeventfd.fd);

#if 0
	vals.i = 1;
	sync_global_to_guest(vcpu->vm, vals);
	while (1) {
		vcpu_run(vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
		if (get_ucall(vcpu, &uc))
			break;

		TEST_ASSERT(run->io.port == 0x80,
			    "Expected I/O at port 0x80, got port 0x%x", run->io.port);
	}
	switch (uc.cmd) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unknown ucall %lu", uc.cmd);
	}
#endif

	kvm_vm_free(vm);
}

int main(int argc, char *argv[]) {
	test_pio_ioeventfd_basic();
}
