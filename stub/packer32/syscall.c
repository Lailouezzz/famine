/**
 * @file syscall.c
 * @brief 32-bit system call wrappers for freestanding packer.
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

#define SYS_READ        3
#define SYS_WRITE       4
#define SYS_OPEN        5
#define SYS_CLOSE       6
#define SYS_LSEEK       19
#define SYS_MMAP2       192
#define SYS_MUNMAP      91
#define SYS_MREMAP      163
#define SYS_MSYNC       144
#define SYS_FTRUNCATE   93
#define SYS_FSTAT64     197
#define SYS_MPROTECT    125
#define SYS_READLINK    85

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
	return (void *)syscall6(SYS_MMAP2, (long)addr, len, prot, flags, fd, off >> 12);
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
	return syscall2(SYS_FSTAT64, fd, (long)st);
}

ssize_t	readlink(const char *restrict path, char *buf, size_t bufsiz)
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
