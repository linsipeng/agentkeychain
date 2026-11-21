#ifndef AKC_PILOT_LINUX_DESCRIPTOR_LAUNCH_H
#define AKC_PILOT_LINUX_DESCRIPTOR_LAUNCH_H

/* Linux only, in a dedicated single-threaded launch child. Caller owns
 * image_fd and must first establish no-follow named provenance. The digest
 * is 32 raw bytes from verified signed installation material. FDs 0–2
 * must already be controlled. Success replaces this process. On failure
 * the caller must exit, never fall back. A static reader or separately
 * validated dynamic-loader and dependency identities remain required. */
int akc_pilot_linux_exec_verified_fd(int image_fd,const unsigned char expected_sha256[32]);

#endif
