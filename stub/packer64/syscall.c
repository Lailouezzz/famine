/**
 * @file syscall.c
 * @brief 64-bit system call wrappers for freestanding packer.
 */

// ---
// Includes
// ---

#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

#include "utils.h"

// ---
// Defines
// ---

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_FSTAT 5
#define SYS_LSEEK 8
#define SYS_MMAP 9
#define SYS_MPROTECT 10
#define SYS_MUNMAP 11
#define SYS_MREMAP 25
#define SYS_MSYNC 26
#define SYS_FTRUNCATE 77
#define SYS_READLINK 89

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
	return (ssize_t)syscall3(SYS_READ, fd, (long)buf, size);
}

ssize_t	write(int fd, const char *buf, size_t size)
{
	return (ssize_t)syscall3(SYS_WRITE, fd, (long)buf, size);
}

int	open(const char *path, int flags, ...)
{
	if (flags & O_CREAT) {
		va_list	va;
		mode_t mode;

		va_start(va, flags);
		mode = va_arg(va, mode_t);
		va_end(va);
		return syscall3(SYS_OPEN, (long)path, flags, mode);
	}
	return syscall2(SYS_OPEN, (long)path, flags);
}

int	close(int fd)
{
	return syscall1(SYS_CLOSE, fd);
}

void	*mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	return (void *)syscall6(SYS_MMAP, (long)addr, len, prot, flags, fd, off);
}

off_t	lseek(int fd, off_t off, int whence)
{
	return syscall3(SYS_LSEEK, fd, off, whence);
}

int	munmap(void *addr, size_t len)
{
	return syscall2(SYS_MUNMAP, (long)addr, len);
}

int	msync(void *addr, size_t len, int flags)
{
	return syscall3(SYS_MSYNC, (long)addr, len, flags);
}

void	*mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...)
{
	if (flags & MREMAP_FIXED) {
		va_list	va;
		void *new_addr;

		va_start(va, flags);
		new_addr = va_arg(va, void *);
		va_end(va);
		return (void *)syscall5(SYS_MREMAP, (long)old_addr, old_size, new_size,
		    flags, (long)new_addr);
	}
	return (void *)syscall4(SYS_MREMAP, (long)old_addr, old_size, new_size, flags);
}

int	fstat(int fd, struct stat *st)
{
	return syscall2(SYS_FSTAT, fd, (long)st);
}

ssize_t	readlink(const char *restrict path, char *buf, int bufsiz)
{
	return syscall3(SYS_READLINK, (long)path, (long)buf, bufsiz);
}

int	mprotect(void *addr, size_t size, int prot)
{
	return syscall3(SYS_MPROTECT, (long)addr, size, prot);
}

// ---
// Static function definitions
// ---

static inline long syscall0(long n)
{
	UNUSED(n);
	long ret;
	asm volatile(
		"syscall"
		: "=a"(ret)
		: "a"(n)
		: "rcx", "r11", "memory"
	);
	if ((unsigned long)ret > (~(0x1000 - 1UL)))
		ret = -1;
	return ret;
}

static inline long syscall1(long n, long a1)
{
	UNUSED(n);
	UNUSED(a1);
	long ret;
	asm volatile(
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1)
		: "rcx", "r11", "memory"
	);
	if ((unsigned long)ret > (~(0x1000 - 1UL)))
		ret = -1;
	return ret;
}

static inline long syscall2(long n, long a1, long a2)
{
	UNUSED(n);
	UNUSED(a1);
	UNUSED(a2);
	long ret;
	asm volatile(
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2)
		: "rcx", "r11", "memory"
	);
	if ((unsigned long)ret > (~(0x1000 - 1UL)))
		ret = -1;
	return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3)
{
	UNUSED(n);
	UNUSED(a1);
	UNUSED(a2);
	UNUSED(a3);
	long ret;
	asm volatile(
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2), "d"(a3)
		: "rcx", "r11", "memory"
	);
	if ((unsigned long)ret > (~(0x1000 - 1UL)))
		ret = -1;
	return ret;
}

static inline long syscall4(long n, long a1, long a2, long a3, long a4)
{
	UNUSED(n);
	UNUSED(a1);
	UNUSED(a2);
	UNUSED(a3);
	UNUSED(a4);
	long ret;
	asm volatile(
		"mov %5, %%r10\n\t"
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4)
		: "rcx", "r10", "r11", "memory"
	);
	if ((unsigned long)ret > (~(0x1000 - 1UL)))
		ret = -1;
	return ret;
}

static inline long syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
	UNUSED(n);
	UNUSED(a1);
	UNUSED(a2);
	UNUSED(a3);
	UNUSED(a4);
	UNUSED(a5);
	long ret;
	asm volatile(
		"mov %5, %%r10\n\t"
		"mov %6, %%r8\n\t"
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5)
		: "rcx", "r10", "r8", "r11", "memory"
	);
	if ((unsigned long)ret > (~(0x1000 - 1UL)))
		ret = -1;
	return ret;
}

static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	UNUSED(n);
	UNUSED(a1);
	UNUSED(a2);
	UNUSED(a3);
	UNUSED(a4);
	UNUSED(a5);
	UNUSED(a6);
	long ret;
	asm volatile(
		"mov %5, %%r10\n\t"
		"mov %6, %%r8\n\t"
		"mov %7, %%r9\n\t"
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5), "r"(a6)
		: "rcx", "r10", "r8", "r9", "r11", "memory"
	);
	if ((unsigned long)ret > (~(0x1000 - 1UL)))
		ret = -1;
	return ret;
}
