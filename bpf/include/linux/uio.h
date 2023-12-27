#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

#include "vmlinux/vmlinux.h"

/* generic data direction definitions */
#define READ			0
#define WRITE			1

static inline enum iter_type iov_iter_type(const struct iov_iter *i)
{
	return i->type & ~(READ | WRITE | ITER_BVEC_FLAG_NO_REF);
}

static inline bool iter_is_iovec(const struct iov_iter *i)
{
	return iov_iter_type(i) == ITER_IOVEC;
}

#endif // __LINUX_UIO_H
