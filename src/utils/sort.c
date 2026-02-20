// ---
// Includes
// ---

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ---
// Static function definitions
// ---

static void	_swap(char *a, char *b, size_t size)
{
	char	tmp[size];

	memcpy(tmp, a, size);
	memcpy(a, b, size);
	memcpy(b, tmp, size);
}

static int	_quicksort_part(char *tab, size_t size, size_t len, size_t pivot, int(*cmp)(const void*, const void*))
{
	size_t	k;
	size_t	p;

	_swap(&tab[pivot * size], &tab[(len - 1) * size], size);
	pivot = len - 1;
	k = 0;
	p = 0;
	while (k < len)
	{
		if (cmp(&tab[k * size], &tab[pivot * size]) < 0)
		{
			_swap(&tab[k * size], &tab[p * size], size);
			++p;
		}
		++k;
	}
	_swap(&tab[pivot * size], &tab[p * size], size);
	return (p);
}
size_t	_pivot_idx(
			void *base,
			size_t size, 
			size_t len,
			int (*cmp)(const void*, const void*)
			) {
	size_t	lo = 0;
	size_t	mid = len / 2;
	size_t	hi = len - 1;

	void *a = base + lo * size;
	void *b = base + mid * size;
	void *c = base + hi * size;

	if (cmp(a, b) > 0) {
		a = (void *)((uintptr_t)b ^ (uintptr_t)a);
		b = (void *)((uintptr_t)b ^ (uintptr_t)a);
		a = (void *)((uintptr_t)b ^ (uintptr_t)a);
		lo ^= mid;
		mid ^= lo;
		lo ^= mid;
	}
	if (cmp(b, c) > 0) {
		c = (void *)((uintptr_t)b ^ (uintptr_t)c);
		b = (void *)((uintptr_t)b ^ (uintptr_t)c);
		c = (void *)((uintptr_t)b ^ (uintptr_t)c);
		hi ^= mid;
		mid ^= hi;
		hi ^= mid;
	}
	if (cmp(a, b) > 0)
		mid = lo;

	return mid;
}

// ---
// Extern function definitions
// ---

void	quicksort(void *tab, size_t size, size_t len, int(*cmp)(const void*, const void*))
{
	size_t	pivot;

	if (len != 0)
	{
		pivot = _pivot_idx(tab, size, len, cmp);
		pivot = _quicksort_part(tab, size, len, pivot, cmp);
		quicksort(tab, size, pivot, cmp);
		quicksort((char *)tab + (pivot + 1) * size, size, len - pivot - 1, cmp);
	}
}
