#ifndef COMMON_H
#define COMMON_H

#include <endian.h>
#include <byteswap.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le_to_host16(n) (n)
#define host_to_le16(n) (n)
#define be_to_host16(n) bswap_16(n)
#define host_to_be16(n) bswap_16(n)
#else
#define le_to_host16(n) bswap_16(n)
#define host_to_le16(n) bswap_16(n)
#define be_to_host16(n) (n)
#define host_to_be16(n) (n)
#endif


#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

/*
 * Definitions for sparse validation
 * (http://kernel.org/pub/linux/kernel/people/josh/sparse/)
 */
#ifdef __CHECKER__
#define __force __attribute__((force))
#undef __bitwise
#define __bitwise __attribute__((bitwise))
#else
#define __force
#undef __bitwise
#define __bitwise
#endif

#ifndef __must_check
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#define __must_check __attribute__((__warn_unused_result__))
#else
#define __must_check
#endif /* __GNUC__ */
#endif /* __must_check */

typedef u16 __bitwise be16;
typedef u16 __bitwise le16;
typedef u32 __bitwise be32;
typedef u32 __bitwise le32;
typedef u64 __bitwise be64;
typedef u64 __bitwise le64;

#ifdef __GNUC__
#define PRINTF_FORMAT(a,b) __attribute__ ((format (printf, (a), (b))))
#define STRUCT_PACKED __attribute__ ((packed))
#else
#define PRINTF_FORMAT(a,b)
#define STRUCT_PACKED
#endif

#include <netinet/in.h>
#if RADIUS_DAS_SUPPORT
#include <radius_das.h>
#endif /* RADIUS_DAS_SUPPORT */

/* Macros for handling unaligned memory accesses */

static inline u16 WPA_GET_BE16(const u8 *a)
{
	return (a[0] << 8) | a[1];
}

static inline void WPA_PUT_BE16(u8 *a, u16 val)
{
	a[0] = val >> 8;
	a[1] = val & 0xff;
}

static inline u16 WPA_GET_LE16(const u8 *a)
{
        return (a[1] << 8) | a[0];
}

static inline void WPA_PUT_LE16(u8 *a, u16 val)
{
        a[1] = val >> 8;
        a[0] = val & 0xff;
}

static inline u32 WPA_GET_BE32(const u8 *a)
{
        return ((u32) a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void WPA_PUT_BE32(u8 *a, u32 val)
{
        a[0] = (val >> 24) & 0xff;
        a[1] = (val >> 16) & 0xff;
        a[2] = (val >> 8) & 0xff;
        a[3] = val & 0xff;
}

static inline u64 WPA_GET_BE64(const u8 *a)
{
        return (((u64) a[0]) << 56) | (((u64) a[1]) << 48) |
                (((u64) a[2]) << 40) | (((u64) a[3]) << 32) |
                (((u64) a[4]) << 24) | (((u64) a[5]) << 16) |
                (((u64) a[6]) << 8) | ((u64) a[7]);
}

static inline void WPA_PUT_BE64(u8 *a, u64 val)
{
        a[0] = val >> 56;
        a[1] = val >> 48;
        a[2] = val >> 40;
        a[3] = val >> 32;
        a[4] = val >> 24;
        a[5] = val >> 16;
        a[6] = val >> 8;
        a[7] = val & 0xff;
}

void hostapd_hexdump(const char *title, u8 *buf, size_t len);
int hwaddr_aton(char *txt, u8 *addr);

static inline void print_char(char c)
{
	if (c >= 32 && c < 127)
		printf("%c", c);
	else
		printf("<%02x>", c);
}

void bin_clear_free(void *bin, size_t len);
int os_get_random(unsigned char *buf, size_t len);
unsigned long os_random(void);

#define random_get_bytes(b, l) os_get_random((b), (l))

#endif /* COMMON_H */
