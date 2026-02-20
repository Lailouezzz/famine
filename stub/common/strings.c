/**
 * @file strings.c
 * @brief String and memory functions for freestanding stub.
 */

#include <stddef.h>

/** @brief Compare memory regions. */
int	memcmp(const void *s1, const void *s2, size_t n)
{
	while (n--) {
		if (*(unsigned char *)s1 != *(unsigned char *)s2)
			return (*(unsigned char *)s1 - *(unsigned char *)s2);
		s1++;
		s2++;
	}
	return 0;
}

/** @brief Compare strings. */
int	strcmp(const char *s1, const char *s2)
{
	while (*s1 && *s2) {
		++s1;
		++s2;
	}
	return *s1 - *s2;
}

/** @brief Copy memory. */
void	*memcpy(void *restrict dst, const void *restrict src, size_t n)
{
	if (!dst && !src)
		return nullptr;
	while (n--)
		((char *)dst)[n] = ((char *)src)[n];
	return dst;
}

/** @brief Move memory (handles overlap). */
void	*memmove(void *dst, const void *src, size_t n)
{
	void	*dst_cpy;

	if (!dst && !src)
		return nullptr;
	dst_cpy = dst;
	if (dst > src && (size_t)(dst - src) < n) {
		dst += n - 1;
		src += n - 1;
		while (n--)
			*(char *)dst-- = *(char *)src--;
	} else {
		while (n--)
			*(char *)dst++ = *(char *)src++;
	}
	return dst_cpy;
}

/** @brief Fill memory with byte. */
void	*memset(void *ptr, int c, size_t n)
{
	while (n)
		((char *)ptr)[--n] = c;
	return ptr;
}

/** @brief Get string length. */
int	strlen(const char *s)
{
	int k = 0;
	while (*(s++))
		++k;
	return k;
}
