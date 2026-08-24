// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/seq_file.h>

#include "common.h"
#include "kvm.h"
#include "inode.h"
#include "trace.h"

struct vkvmfs_mount_opts {
	u64 partition;
};

struct vkvmfs_fs_info {
	struct vkvmfs_mount_opts mount_opts;
	struct virtio_kvm_partition *part;
};

struct kvm_guest_memory_file {
	u64 handle;
	unsigned long pfn;
	unsigned long size;
	struct virtio_kvm_partition *part;
};

#define VKVMFS_DEFAULT_MODE	0755
#define VKVMFS_MAGIC 0x4d564b56 /* "VKVM" */

static const struct super_operations vkvmfs_ops;
static const struct inode_operations vkvmfs_dir_inode_operations;
static const struct address_space_operations vkvmfs_aops = {
	.dirty_folio	= noop_dirty_folio,
};

static int
virtio_kvm_memory_file_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct kvm_guest_memory_file *gfile =
		(struct kvm_guest_memory_file *)filp->private_data;
	int err;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	if ((vma->vm_pgoff << PAGE_SHIFT) + (vma->vm_end - vma->vm_start)
			> gfile->size)
		return -EINVAL;

	err = remap_pfn_range(vma, vma->vm_start, gfile->pfn + vma->vm_pgoff,
			      vma->vm_end - vma->vm_start, vma->vm_page_prot);
	if (WARN_ON_ONCE(err))
		return err;

	return 0;
}

bool virtio_kvm_is_vkvmfs(struct file *filp)
{
	if (!filp || !filp->private_data)
		return false;

	if (!filp->f_op)
		return false;

	/*
	 * Both anon gfiles and linked gfiles use the same mmap routine.
	 */
	return filp->f_op->mmap == virtio_kvm_memory_file_mmap;
}

int vkvmfs_offset_to_pa(struct file *filp, off_t offset, size_t size, unsigned long *pa)
{
	struct kvm_guest_memory_file *gfile = (struct kvm_guest_memory_file *)filp->private_data;

	if (offset + size > gfile->size)
		return -E2BIG;

	*pa = (gfile->pfn << PAGE_SHIFT) + offset;
	return 0;
}

static int vkvmfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			  struct iattr *attr);

static const struct inode_operations vkvmfs_file_inode_operations = {
	.setattr = vkvmfs_setattr,
};
static const struct file_operations vkvmfs_file_operations = {
	.mmap = virtio_kvm_memory_file_mmap,
	.open = simple_open,
	.llseek = default_llseek,
};

static int virtio_kvm_delete_memory_file(u64 handle, u64 size, u64 pfn)
{
	u64 offset = (pfn << PAGE_SHIFT) - vi_device->phys_start;
	int ret;

	/*
	 * May be called in atomic context; delete the memory file
	 * asynchronously.
	 */
	ret = virtio_kvm_send_command(handle,
				      VIRTIO_VM_MEMORY_FILE_DELETE,
				      0, size, NULL);
	virtio_vm_put_unused_phys_offset(offset, size);
	return ret;
}

static int virtio_kvm_init_memory_file_pdata(void **private_data)
{
	struct kvm_guest_memory_file *gfile;

	*private_data = NULL;

	gfile = (struct kvm_guest_memory_file *)kmalloc(sizeof(*gfile), GFP_KERNEL);
	if (!gfile)
		return -ENOMEM;

	gfile->size = 0;
	*private_data = (void *)gfile;

	return 0;
}

static int virtio_kvm_create_memory_file(struct kvm_guest_memory_file *gfile,
				  unsigned long size, u64 partition_id)
{
	u64 phys_offset;
	int err;

	struct kvm_guest_memory_file_io {
		u64 size;		/* in */
		u64 phys_offset;	/* in */
		u64 handle;		/* out */
	};
	struct kvm_guest_memory_file_io *h;

	if (WARN_ON_ONCE(!size))
		return -EINVAL;

	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return -ENOMEM;

	/* Need an alignment of 1GiB to be able to guarantee GB pages. */
	phys_offset = virtio_vm_get_unused_phys_offset(size, BAR_GUEST_MEM_ALIGNMENT_ORDER);
	if (phys_offset == INVALID_PHYS_OFFSET) {
		kfree(h);
		return -ENOMEM;
	}

	h->size = size;
	h->phys_offset = phys_offset;

	err = virtio_kvm_send_command(-1, VIRTIO_VM_MEMORY_FILE_CREATE, partition_id,
				      __pa(h), NULL);
	if (err) {
		virtio_vm_put_unused_phys_offset(phys_offset, size);
		kfree(h);
		return err;
	}

	gfile->size = h->size;
	gfile->pfn = (phys_offset + vi_device->phys_start) >> PAGE_SHIFT;
	gfile->handle = h->handle;
	gfile->part = virtkvm_partition_get_by_id(vi_device, partition_id);

	pr_debug("guest memory file placed at %lx\n", gfile->pfn);

	kfree(h);

	return 0;
}

/*
 * Only for anonymous memory files.
 */
static int
virtio_kvm_memory_file_release(struct inode *inode, struct file *filp)
{
	struct kvm_guest_memory_file *gfile;
	int err = 0;

	gfile = filp->private_data;
	if (!gfile)
		return 0;

	if (gfile->size) {
		err = virtio_kvm_delete_memory_file(gfile->handle, gfile->size, gfile->pfn);
		WARN_ONCE(err, "Failed to release memory file %llx: %d\n",
				gfile->handle, err);
	}

	virtkvm_partition_put(gfile->part);
	kfree(gfile);
	return err;
}


const struct file_operations kvm_memory_anonfile_fops = {
	.release = virtio_kvm_memory_file_release,
	.mmap = virtio_kvm_memory_file_mmap,
};

int virtio_kvm_create_memory_anonfile(unsigned long size, u64 partition_id)
{
	struct file *file;
	int fd, ret;

	if (!size)
		return -EINVAL;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;

	file = anon_inode_getfile("kvm-memory-file", &kvm_memory_anonfile_fops,
				  NULL, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_fd;
	}

	ret = virtio_kvm_init_memory_file_pdata(&file->private_data);
	if (ret)
		goto err;
	ret = virtio_kvm_create_memory_file(
			(struct kvm_guest_memory_file *)file->private_data,
			size, partition_id);
	if (ret)
		goto err;

	fd_install(fd, file);
	return fd;

err:
	fput(file);
err_fd:
	put_unused_fd(fd);
	return ret;
}

static int vkvmfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			  struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(idmap, dentry, attr);
	if (error)
		return error;

	if (ia_valid & ATTR_SIZE) {
		struct vkvmfs_fs_info *fsi = dentry->d_sb->s_fs_info;
		struct kvm_guest_memory_file *gfile;
		loff_t oldsize = inode->i_size;
		loff_t newsize = attr->ia_size;

		gfile = inode->i_private;

		/* Resizing from zero is allowed. */
		if (oldsize)
			return -EINVAL;

		if (!newsize)
			goto out;

		error = virtio_kvm_create_memory_file(gfile, newsize,
						      fsi->mount_opts.partition);
		if (error)
			return error;

		inode->i_size = newsize;
	}

out:
	setattr_copy(idmap, inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

static struct inode *vkvmfs_get_inode(struct mnt_idmap *idmap,
				      struct super_block *sb,
				      const struct inode *dir, umode_t mode,
				      dev_t dev)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode_init_owner(idmap, inode, dir, mode);
		inode->i_mapping->a_ops = &vkvmfs_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		simple_inode_init_ts(inode);
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_op = &vkvmfs_file_inode_operations;
			inode->i_fop = &vkvmfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &vkvmfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		}
	}
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
vkvmfs_mknod(struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode * inode = vkvmfs_get_inode(idmap, dir->i_sb, dir, mode, dev);
	int error = -ENOSPC;

	if (!inode)
		return error;

	error = security_inode_init_security(inode, dir,
					     &dentry->d_name, NULL,
					     NULL);
	if (error)
		goto err;

	if (S_ISREG(mode)) {
		/* Prepare the gfile for a later resize. */
		error = virtio_kvm_init_memory_file_pdata(&inode->i_private);
		if (error)
			goto err;
	}

	d_make_persistent(dentry, inode);
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	return 0;
err:
	iput(inode);
	return error;
}

static struct dentry *vkvmfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
				 struct dentry *dentry, umode_t mode)
{
	int retval = vkvmfs_mknod(idmap, dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		inc_nlink(dir);
	return ERR_PTR(retval);
}

static int vkvmfs_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode)
{
	return vkvmfs_mknod(idmap, dir, dentry, mode | S_IFREG, 0);
}

static const struct inode_operations vkvmfs_dir_inode_operations = {
	.create		= vkvmfs_create,
	.lookup		= simple_lookup,
	.link		= simple_link,
	.unlink		= simple_unlink,
	.mkdir		= vkvmfs_mkdir,
	.rmdir		= simple_rmdir,
	.mknod		= vkvmfs_mknod,
	.rename		= simple_rename,
};

/*
 * Display the mount options in /proc/mounts.
 */
static int vkvmfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct vkvmfs_fs_info *fsi = root->d_sb->s_fs_info;

	seq_printf(m, ",partition=%llu", fsi->mount_opts.partition);
	return 0;
}

static void vkvmfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	if (inode->i_private) {
		struct kvm_guest_memory_file *gfile = inode->i_private;
		int error;

		if (gfile->size) {
			error = virtio_kvm_delete_memory_file(gfile->handle,
							      gfile->size,
							      gfile->pfn);
			WARN_ON_ONCE(error);
			gfile->size = 0;
		}

		virtkvm_partition_put(gfile->part);
		kfree(gfile);
	}
}

static const struct super_operations vkvmfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= inode_just_drop,
	.evict_inode	= vkvmfs_evict_inode,
	.show_options	= vkvmfs_show_options,
};

enum vkvmfs_param {
	Opt_partition,
};

const struct fs_parameter_spec vkvmfs_fs_parameters[] = {
	fsparam_u64("partition",	Opt_partition),
	{}
};

static int vkvmfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct vkvmfs_fs_info *fsi = fc->s_fs_info;
	int opt;

	opt = fs_parse(fc, vkvmfs_fs_parameters, param, &result);
	if (opt == -ENOPARAM) {
		opt = vfs_parse_fs_param_source(fc, param);
		if (opt != -ENOPARAM)
			return opt;

		pr_err("unknown parameter for vkvmfs: %s\n", param->key);
		return 0;
	}
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_partition:
		fsi->mount_opts.partition = result.uint_64;
		break;
	}

	return 0;
}

static int vkvmfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct vkvmfs_fs_info *fsi = sb->s_fs_info;
	struct inode *inode;

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= PAGE_SHIFT;
	sb->s_magic		= VKVMFS_MAGIC;
	sb->s_op		= &vkvmfs_ops;
	sb->s_time_gran		= 1;

	fsi->part = virtkvm_partition_get_by_id(vi_device, fsi->mount_opts.partition);

	inode = vkvmfs_get_inode(&nop_mnt_idmap, sb, NULL, S_IFDIR | VKVMFS_DEFAULT_MODE, 0);
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		virtkvm_partition_put(fsi->part);
		return -ENOMEM;
	}

	return 0;
}

static int vkvmfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, vkvmfs_fill_super);
}

static void vkvmfs_free_fc(struct fs_context *fc)
{
	kfree(fc->s_fs_info);
}

static const struct fs_context_operations vkvmfs_context_ops = {
	.free		= vkvmfs_free_fc,
	.parse_param	= vkvmfs_parse_param,
	.get_tree	= vkvmfs_get_tree,
};

static int vkvmfs_init_fs_context(struct fs_context *fc)
{
	struct vkvmfs_fs_info *fsi;

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	if (!fsi)
		return -ENOMEM;

	fsi->mount_opts.partition = 0;
	fc->s_fs_info = fsi;
	fc->ops = &vkvmfs_context_ops;
	return 0;
}

static void vkvmfs_kill_sb(struct super_block *sb)
{
	struct vkvmfs_fs_info *fsi = sb->s_fs_info;

	if (fsi)
		virtkvm_partition_put(fsi->part);
	kill_anon_super(sb);
	kfree(fsi);
}

static struct file_system_type vkvmfs_fs_type = {
	.name		= "vkvmfs",
	.init_fs_context = vkvmfs_init_fs_context,
	.parameters	= vkvmfs_fs_parameters,
	.kill_sb	= vkvmfs_kill_sb,
};

static int __init init_vkvmfs_fs(void)
{
	return register_filesystem(&vkvmfs_fs_type);
}
fs_initcall(init_vkvmfs_fs);
