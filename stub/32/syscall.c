/**
 * @file syscall.c
 * @brief 32-bit system call wrappers for freestanding stub.
 */

// ---
// Includes
// ---

#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "utils.h"

// ---
// Defines
// ---

#define MREMAP_FIXED 0x2

// ---
// Static function declarations
// ---

static inline long syscall0(long n);
static inline long syscall1(long n, long a1);
static inline long syscall2(long n, long a1, long a2);
static inline long syscall3(long n, long a1, long a2, long a3);
static inline long syscall4(long n, long a1, long a2, long a3, long a4);
static inline long syscall5(long n, long a1, long a2, long a3, long a4, long a5);
static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6);

// ---
// Extern function definitions
// ---

ssize_t	read(int fd, char *buf, size_t size)
{
	return (ssize_t)syscall3(SYS_read, fd, (long)buf, size);
}

ssize_t	write(int fd, const char *buf, size_t size)
{
	return (ssize_t)syscall3(SYS_write, fd, (long)buf, size);
}

int	open(const char *path, int flags, ...)
{
	if (flags & O_CREAT) {
		va_list	va;
		mode_t mode;

		va_start(va, flags);
		mode = va_arg(va, mode_t);
		va_end(va);
		return syscall3(SYS_open, (long)path, flags, mode);
	}
	return syscall2(SYS_open, (long)path, flags);
}

int	close(int fd)
{
	return syscall1(SYS_close, fd);
}

void	*mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	return (void *)syscall6(SYS_mmap2, (long)addr, len, prot, flags, fd, off >> 12);
}

off_t	lseek(int fd, off_t off, int whence)
{
	return syscall3(SYS_lseek, fd, off, whence);
}

int	munmap(void *addr, size_t len)
{
	return syscall2(SYS_munmap, (long)addr, len);
}

int	msync(void *addr, size_t len, int flags)
{
	return syscall3(SYS_msync, (long)addr, len, flags);
}

int	mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...)
{
	if (flags & MREMAP_FIXED) {
		va_list	va;
		void *new_addr;

		va_start(va, flags);
		new_addr = va_arg(va, void *);
		va_end(va);
		return syscall5(SYS_mremap, (long)old_addr, old_size, new_size,
		    flags, (long)new_addr);
	}
	return syscall4(SYS_mremap, (long)old_addr, old_size, new_size, flags);
}

int	fstat(int fd, struct stat *st)
{
	return syscall2(SYS_fstat64, fd, (long)st);
}

ssize_t	readlink(const char *restrict path, char *buf, size_t bufsiz)
{
	return syscall3(SYS_readlink, (long)path, (long)buf, bufsiz);
}

int	mprotect(void *addr, size_t size, int prot)
{
	return syscall3(SYS_mprotect, (long)addr, size, prot);
}

ssize_t getdents64(int fd, void *dirp, size_t count)
{
	return syscall3(SYS_getdents64, fd, (long)dirp, count);
}

// ---
// Static function definitions
// ---

static inline long syscall0(long n)
{
	long ret;
	__asm__ volatile (
		"int $0x80"
		: "=a"(ret)
		: "a"(n)
		: "memory"
	);
	return ret;
}

static inline long syscall1(long n, long a1)
{
	long ret;
	__asm__ volatile (
		"int $0x80"
		: "=a"(ret)
		: "a"(n), "b"(a1)
		: "memory"
	);
	return ret;
}

static inline long syscall2(long n, long a1, long a2)
{
	long ret;
	__asm__ volatile (
		"int $0x80"
		: "=a"(ret)
		: "a"(n), "b"(a1), "c"(a2)
		: "memory"
	);
	return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3)
{
	long ret;
	__asm__ volatile (
		"int $0x80"
		: "=a"(ret)
		: "a"(n), "b"(a1), "c"(a2), "d"(a3)
		: "memory"
	);
	return ret;
}

static inline long syscall4(long n, long a1, long a2, long a3, long a4)
{
	long ret;
	__asm__ volatile (
		"int $0x80"
		: "=a"(ret)
		: "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4)
		: "memory"
	);
	return ret;
}

static inline long syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
	long ret;
	__asm__ volatile (
		"int $0x80"
		: "=a"(ret)
		: "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5)
		: "memory"
	);
	return ret;
}

static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	__asm__ volatile (
		"push %%ebp\n\t"
		"mov %[a6], %%ebp\n\t"
		"int $0x80\n\t"
		"pop %%ebp"
		: "=a"(ret)
		: "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5), [a6]"m"(a6)
		: "memory"
	);
	return ret;
}
