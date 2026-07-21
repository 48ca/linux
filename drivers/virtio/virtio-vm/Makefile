obj-$(CONFIG_VIRTIO_VM) += common.o
obj-$(CONFIG_VIRTIO_VM) += kvm.o
obj-$(CONFIG_VIRTIO_VM) += vfio.o
obj-$(CONFIG_VIRTIO_VM) += modparam/kvm.o
obj-$(CONFIG_VIRTIO_VM) += modparam/kvm-intel.o
obj-$(CONFIG_VIRTIO_VM) += modparam/kvm-amd.o
obj-$(CONFIG_VIRTIO_VM) += inode.o

CFLAGS_common.o = -I$(src)
CFLAGS_kvm.o = -I$(src)
CFLAGS_vfio.o = -I$(src)
CFLAGS_inode.o = -I$(src)
