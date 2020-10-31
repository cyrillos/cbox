#ifndef TARANTOOL_CONFIG_H_INCLUDED
#define TARANTOOL_CONFIG_H_INCLUDED
/*
 * This file is generated by CMake. The original file is called
 * config.h.cmake. Please do not modify.
 */
/** \cond public */

/**
 * Package major version - 1 for 1.6.7
 */
#define PACKAGE_VERSION_MAJOR 2
/**
 * Package minor version - 6 for 1.6.7
 */
#define PACKAGE_VERSION_MINOR 7
/**
 * Package patch version - 7 for 1.6.7
 */
#define PACKAGE_VERSION_PATCH 0
/**
 * A string with major-minor-patch-commit-id identifier of the
 * release, e.g. 1.6.6-113-g8399d0e.
 */
#define PACKAGE_VERSION "2.7.0-4-g42374a161"

/** \endcond public */

#define PACKAGE "Tarantool"
/*  Defined if building for Linux */
#define TARGET_OS_LINUX 1
/*  Defined if building for FreeBSD */
/* #undef TARGET_OS_FREEBSD */
/*  Defined if building for NetBSD */
/* #undef TARGET_OS_NETBSD */
/*  Defined if building for Darwin */
/* #undef TARGET_OS_DARWIN */

#ifdef TARGET_OS_DARWIN
#define TARANTOOL_LIBEXT "dylib"
#else
#define TARANTOOL_LIBEXT "so"
#endif

/**
 * Defined if cpuid() instruction is available.
 */
#define HAVE_CPUID 1

/*
 * Defined if gcov instrumentation should be enabled.
 */
/* #undef ENABLE_GCOV */
/*
 * Defined if configured with ENABLE_BACKTRACE ('show fiber'
 * showing fiber call stack.
 */
#define ENABLE_BACKTRACE 1
/*
 * Set if the system has bfd.h header and GNU bfd library.
 */
/* #undef HAVE_BFD */
#define HAVE_MAP_ANON 1
#define HAVE_MAP_ANONYMOUS 1
#if !defined(HAVE_MAP_ANONYMOUS) && defined(HAVE_MAP_ANON)
/*
 * MAP_ANON is deprecated, MAP_ANONYMOUS should be used instead.
 * Unfortunately, it's not universally present (e.g. not present
 * on FreeBSD.
 */
#define MAP_ANONYMOUS MAP_ANON
#endif
#define HAVE_MADV_DONTNEED 1
/*
 * Defined if O_DSYNC mode exists for open(2).
 */
#define HAVE_O_DSYNC 1
#if defined(HAVE_O_DSYNC)
    #define WAL_SYNC_FLAG O_DSYNC
#else
    #define WAL_SYNC_FLAG O_SYNC
#endif
/*
 * Defined if fdatasync(2) call is present.
 */
#define HAVE_FDATASYNC 1

#ifndef HAVE_FDATASYNC
#if defined(__APPLE__)
#include <fcntl.h>
#define fdatasync(fd) fcntl(fd, F_FULLFSYNC)
#else
#define fdatasync fsync
#endif
#endif

/*
 * Defined if this platform has GNU specific memmem().
 */
#define HAVE_MEMMEM 1
/*
 * Defined if this platform has GNU specific memrchr().
 */
#define HAVE_MEMRCHR 1
/*
 * Defined if this platform has sendfile(..).
 */
#define HAVE_SENDFILE 1
/*
 * Defined if this platform has Linux specific sendfile(..).
 */
#define HAVE_SENDFILE_LINUX 1
/*
 * Defined if this platform has BSD specific sendfile(..).
 */
/* #undef HAVE_SENDFILE_BSD */
/*
 * Set if this is a GNU system and libc has __libc_stack_end.
 */
#define HAVE_LIBC_STACK_END 1
/*
 * Defined if this is a big-endian system.
 */
/* #undef HAVE_BYTE_ORDER_BIG_ENDIAN */
/*
 * Defined if this platform supports openmp and it is enabled
 */
#define HAVE_OPENMP 1
/*
*  Defined if compatible with GNU readline installed.
*/
#define HAVE_GNU_READLINE 1

/*
 * Defined if `st_mtim' is a member of `struct stat'.
 */
#define HAVE_STRUCT_STAT_ST_MTIM 1

/*
 * Defined if `st_mtimensec' is a member of `struct stat'.
 */
/* #undef HAVE_STRUCT_STAT_ST_MTIMENSEC */

/*
 * Set if compiler has __builtin_XXX methods.
 */
#define HAVE_BUILTIN_CTZ 1
#define HAVE_BUILTIN_CTZLL 1
#define HAVE_BUILTIN_CLZ 1
#define HAVE_BUILTIN_CLZLL 1
#define HAVE_BUILTIN_POPCOUNT 1
#define HAVE_BUILTIN_POPCOUNTLL 1
#define HAVE_BUILTIN_BSWAP32 1
#define HAVE_BUILTIN_BSWAP64 1
/* #undef HAVE_FFSL */
/* #undef HAVE_FFSLL */

/*
 * pthread have problems with -std=c99
 */
/* #undef HAVE_NON_C99_PTHREAD_H */

#define ENABLE_BUNDLED_LIBEV 1
#define ENABLE_BUNDLED_LIBEIO 1
#define ENABLE_BUNDLED_LIBCORO 1

#define HAVE_PTHREAD_YIELD 1
#define HAVE_SCHED_YIELD 1
#define HAVE_POSIX_FADVISE 1
#define HAVE_FALLOCATE 1
#define HAVE_MREMAP 1
#define HAVE_SYNC_FILE_RANGE 1

#define HAVE_MSG_NOSIGNAL 1
/* #undef HAVE_SO_NOSIGPIPE */

#define HAVE_PRCTL_H 1

/* #undef HAVE_UUIDGEN */
#define HAVE_CLOCK_GETTIME 1
#define HAVE_CLOCK_GETTIME_DECL 1

/** pthread_np.h - non-portable stuff */
/* #undef HAVE_PTHREAD_NP_H */
/** pthread_setname_np(pthread_self(), "") - Linux */
#define HAVE_PTHREAD_SETNAME_NP 1
/** pthread_setname_np("") - OSX */
/* #undef HAVE_PTHREAD_SETNAME_NP_1 */
/** pthread_set_name_np(pthread_self(), "") - *BSD */
/* #undef HAVE_PTHREAD_SET_NAME_NP */

#define HAVE_PTHREAD_GETATTR_NP 1
/* #undef HAVE_PTHREAD_ATTR_GET_NP */

/* #undef HAVE_PTHREAD_GET_STACKSIZE_NP */
/* #undef HAVE_PTHREAD_GET_STACKADDR_NP */

/* #undef HAVE_SETPROCTITLE */
/* #undef HAVE_SETPROGNAME */
/* #undef HAVE_GETPROGNAME */

/*
 * Defined if ICU library has ucol_strcollUTF8 method.
 */
#define HAVE_ICU_STRCOLLUTF8 1

/*
* Defined if notifications on NOTIFY_SOCKET are enabled
 */
#define WITH_NOTIFY_SOCKET 1

/** \cond public */

/** System configuration dir (e.g /etc) */
#define SYSCONF_DIR "etc"
/** Install prefix (e.g. /usr) */
#define INSTALL_PREFIX "/usr/local"
/** Build type, e.g. Debug or Release */
#define BUILD_TYPE "Debug"
/** CMake build type signature, e.g. Linux-x86_64-Debug */
#define BUILD_INFO "Linux-x86_64-Debug"
/** Command line used to run CMake */
#define BUILD_OPTIONS "cmake . -DCMAKE_INSTALL_PREFIX=/usr/local -DENABLE_BACKTRACE=ON"
/** Pathes to C and CXX compilers */
#define COMPILER_INFO "/usr/bin/cc /usr/bin/c++"
/** C compile flags used to build Tarantool */
#define TARANTOOL_C_FLAGS " -fexceptions -funwind-tables -fno-omit-frame-pointer -fno-stack-protector -fno-common -fopenmp -msse2 -std=c11 -Wall -Wextra -Wno-strict-aliasing -Wno-char-subscripts -Wno-format-truncation -Wno-gnu-alignof-expression -fno-gnu89-inline -Wno-cast-function-type -Werror"
/** CXX compile flags used to build Tarantool */
#define TARANTOOL_CXX_FLAGS " -fexceptions -funwind-tables -fno-omit-frame-pointer -fno-stack-protector -fno-common -fopenmp -msse2 -std=c++11 -Wall -Wextra -Wno-strict-aliasing -Wno-char-subscripts -Wno-format-truncation -Wno-invalid-offsetof -Wno-gnu-alignof-expression -Wno-cast-function-type -Werror"

/** A path to install *.lua module files */
#define MODULE_LIBDIR "/usr/local/lib64/tarantool"
/** A path to install *.so / *.dylib module files */
#define MODULE_LUADIR "/usr/local/share/tarantool"
/** A path to Lua includes (the same directory where this file is contained) */
#define MODULE_INCLUDEDIR "/usr/local/include/tarantool"
/** A constant added to package.path in Lua to find *.lua module files */
#define MODULE_LUAPATH "/usr/local/share/tarantool/?.lua;/usr/local/share/tarantool/?/init.lua;/usr/share/tarantool/?.lua;/usr/share/tarantool/?/init.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;/usr/share/lua/5.1/?.lua;/usr/share/lua/5.1/?/init.lua"
/** A constant added to package.cpath in Lua to find *.so module files */
#define MODULE_LIBPATH "/usr/local/lib64/tarantool/?.so;/usr/lib64/tarantool/?.so;/usr/local/lib64/lua/5.1/?.so;/usr/lib64/lua/5.1/?.so"
/** Shared library suffix - ".so" on Linux, ".dylib" on Mac */
#define MODULE_LIBSUFFIX ".so"

/** \endcond public */

#define DEFAULT_CFG_FILENAME "tarantool.cfg"
#define DEFAULT_CFG SYSCONF_DIR "/" DEFAULT_CFG_FILENAME

/* #undef ENABLE_ASAN */

/* Cacheline size to calculate alignments */
#define CACHELINE_SIZE 64

#define ENABLE_FEEDBACK_DAEMON 1

/*
 * vim: syntax=c
 */
#endif /* TARANTOOL_CONFIG_H_INCLUDED */
