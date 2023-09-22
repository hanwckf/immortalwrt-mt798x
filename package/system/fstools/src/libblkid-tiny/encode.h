#ifndef _ENCODE_H
#define _ENCODE_H

#define BLKID_ENC_UTF16BE	0
#define BLKID_ENC_UTF16LE	1
#define BLKID_ENC_LATIN1	2

size_t blkid_encode_to_utf8(int enc, unsigned char *dest, size_t len,
				const unsigned char *src, size_t count);

#endif /* _ENCODE_H */