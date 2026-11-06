/* Only ABI declarations: compilation does not depend on a system SDK. */
extern int openat(int, const char *, int, ...);
extern int linkat(int, const char *, int, const char *, int);
extern int unlinkat(int, const char *, int);
#ifdef AKC_DARWIN
extern int *__error(void);
#define errno (*__error())
#else
extern int *__errno_location(void);
#define errno (*__errno_location())
#endif
/* Fixed ABI wrapper: openat is variadic (not directly callable via FFI on arm64). */
int akc_openat(int directory, const char *name, int flags, unsigned int mode) {
    int fd = openat(directory, name, flags, mode);
    return fd < 0 ? -errno : fd;
}
int akc_linkat(int directory, const char *source, const char *target) {
    return linkat(directory, source, directory, target, 0) < 0 ? -errno : 0;
}
int akc_unlinkat(int directory, const char *name) {
    return unlinkat(directory, name, 0) < 0 ? -errno : 0;
}
