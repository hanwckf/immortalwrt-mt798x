#include <sys/time.h>
#include "includes.h"
#include "common.h"
#include "rtdot1x.h"


void bin_clear_free(void *bin, size_t len)
{
        if (bin) {
                memset(bin, 0, len);
                free(bin);
        }
}

int RTDebugLevel;
void hex_dump(char *str, const unsigned char *pSrcBufVA, unsigned int SrcBufLen)
{
	unsigned char *pt;
	int x;

	if (RTDebugLevel < RT_DEBUG_TRACE)
		return;

	pt = pSrcBufVA;
	printf("%s: %p, len = %d\n", str, pSrcBufVA, SrcBufLen);

	for (x = 0; x < SrcBufLen; x++) {
		if (x % 16 == 0)
			printf("0x%04x : ", x);

		printf("%02x ", ((unsigned char)pt[x]));

		if (x % 16 == 15)
			printf("\n");
	}

	printf("\n");
}

void * os_memdup(const void *src, size_t len)
{
        void *r = malloc(len);

        if (r)
                memcpy(r, src, len);
        return r;
}

void * os_zalloc(size_t size)
{
        void *ptr = malloc(size);
        if (ptr)
                memset(ptr, 0, size);
        return ptr;
}

int os_get_random(unsigned char *buf, size_t len)
{
	FILE *f;
	size_t rc;

	f = fopen("/dev/urandom", "rb");
	if (f == NULL) {
		printf("Could not open /dev/urandom.\n");
		return -1;
	}

	rc = fread(buf, 1, len, f);
	if (rc != len) {
		(void)fclose(f);
		return -1;
	}

	(void)fclose(f);
	return 0;
}

unsigned long os_random(void)
{
	static int initialized = 0;
	int fd = 0;
	time_t seed = 0;

	if (!initialized) {
		fd = open("/dev/urandom", 0);
		if (fd < 0 || read(fd, &seed, sizeof(seed)) < 0) {
			printf("Could not load seed from /dev/urandom: %s", strerror(errno));
			seed = time(0);
			if (seed == (time_t)(-1))
				DBGPRINT(RT_DEBUG_ERROR, "Unexpected get time fail!\n");
		}
		if (fd >= 0)
			close(fd);
		srand(seed);
		initialized++;
	}

	return rand();
}


size_t os_strlcpy(char *dest, const char *src, size_t siz)
{
        const char *s = src;
        size_t left = siz;

        if (left) {
                /* Copy string up to the maximum size of the dest buffer */
                while (--left != 0) {
                        if ((*dest++ = *s++) == '\0')
                                break;
                }
        }

        if (left == 0) {
                /* Not enough room for the string; force NUL-termination */
                if (siz != 0)
                        *dest = '\0';
                while (*s++)
                        ; /* determine total src string length */
        }

        return s - src - 1;
}
