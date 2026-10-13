obj-$(CONFIG_VIRTIO_VM) += virtio-vm.o
obj-$(CONFIG_VIRTIO_VM) += modparam/kvm.o
obj-$(CONFIG_VIRTIO_VM) += modparam/kvm-intel.o
obj-$(CONFIG_VIRTIO_VM) += modparam/kvm-amd.o

virtio-vm-y := common.o kvm.o vfio.o inode.o

CFLAGS_common.o = -I$(src)
CFLAGS_kvm.o = -I$(src)
CFLAGS_vfio.o = -I$(src)
CFLAGS_inode.o = -I$(src)
