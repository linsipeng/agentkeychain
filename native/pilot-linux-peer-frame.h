#ifndef AKC_PILOT_LINUX_PEER_FRAME_H
#define AKC_PILOT_LINUX_PEER_FRAME_H
#include <stddef.h>
#include <sys/types.h>

#define AKC_PILOT_PEER_MAX_FRAME 2048U
struct akc_pilot_peer { pid_t pid; uid_t uid; gid_t gid; };
/* Call only on a launcher-owned anonymous pair under one unprivileged UID.
 * Exact child must remain unreaped. Fail closed and close the pair on error. */
int akc_pilot_peer_pair(int pair[2]);
/* One exchange only: send one packet then shut down this write half. */
int akc_pilot_peer_send(int fd,const unsigned char *bytes,size_t len);
/* Return authenticated packet byte count; never modify out on denial. */
ssize_t akc_pilot_peer_recv(int fd,struct akc_pilot_peer expected,unsigned char *out,size_t capacity);

#endif
