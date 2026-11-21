#ifndef AKC_PILOT_LINUX_INSPECT_WIRE_H
#define AKC_PILOT_LINUX_INSPECT_WIRE_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/types.h>
#define AKC_INSPECT_WIRE_MAX 2048U

/* Supply from the verified installation and held directory, never the request. */
struct akc_inspect_scope {
 char installation_digest[65];
 char profile_digest[65];
 unsigned char reader_public[32];
 int64_t not_after;
};
enum akc_inspect_status { AKC_INSPECT_UNAVAILABLE=0, AKC_INSPECT_EMPTY,
 AKC_INSPECT_SNAPSHOT_PRESENT, AKC_INSPECT_ROLLBACK_JOURNAL_PRESENT };
typedef enum akc_inspect_status (*akc_inspect_read)(void *held_store);
/* Caller must authenticate the fresh kernel peer before this single call and
 * keep verified storage and lease held through signing. No generic sign route. */
ssize_t akc_inspect_respond(const struct akc_inspect_scope *scope,EVP_PKEY *reader,
 akc_inspect_read read_status,void *held_store,const unsigned char *request,size_t length,
 unsigned char *reply,size_t capacity);
#endif
