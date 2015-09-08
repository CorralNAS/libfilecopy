#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#ifdef __BLOCKS__
# include <Block.h>
#endif
#include <errno.h>

#include <sys/stat.h>
#include <sys/extattr.h>
#include <sys/acl.h>

#include "filecopy.h"

typedef enum {
	TYPE_UNKNOWN = 0,
	TYPE_DIR,
	TYPE_FILE,
	TYPE_LINK,
} ftype_t;

#define FLAG_CREATED	0x00001

struct file_state {
	const char *name;
	struct stat sbuf;
	ftype_t type;
	int flags;
	int fd;
};

struct filecopy_options {
	int	data:1,
		xattr:1,
		acl:1,
		posix:1,
		times:1,
		recursion:1,
		remove:1,
		exclusive:1,
		follow:1;
	void	*context;
	filecopy_status_t	(*statuscb)(const char *, void *, ...);
	filecopy_status_t	(*errorcb)(const char *, void *, ...);
#ifdef __BLOCKS__
	filecopy_status_t	(^status_b)(const char *, ...);
	filecopy_status_t	(^error_b)(const char *, ...);
#else
	void *status_b;
	void *error_b;
#endif
	struct file_state src;
	struct file_state dst;
};

static struct filecopy_options options_default = {
	.data = 1,
	.xattr = 1,
	.acl = 1,
	.posix = 1,
	.times = 1,
	.recursion = 0,
	.follow = 1,
	.src = {
		.fd = -1,
		.type = TYPE_UNKNOWN,
	},
	.dst = {
		.fd = -1,
		.type = TYPE_UNKNOWN,
	},
};
	
//#define DECL(name) const char *name __attribute__((section(".rodata"))) = #name
#define DECL(name) const char *name = #name
DECL(fc_option_data);
DECL(fc_option_xattr);
DECL(fc_option_acl);
DECL(fc_option_perms);
DECL(fc_option_times);
DECL(fc_option_recursion);
DECL(fc_option_follow);
DECL(fc_option_remove);
DECL(fc_option_exclusive);

DECL(fc_option_context);

DECL(fc_option_status_cb);
DECL(fc_option_error_cb);

DECL(fc_option_status_block);
DECL(fc_option_error_block);

DECL(fc_status_data_start);
DECL(fc_status_data_progress);
DECL(fc_status_data_completion);

DECL(fc_error_preparation);
DECL(fc_error_data);

DECL(fc_status_extattr_start);
DECL(fc_error_extattr);
DECL(fc_status_extattr);
DECL(fc_status_extattr_completion);

filecopy_options_t
filecopy_options_init(void)
{
	filecopy_options_t retval = NULL;

	retval = malloc(sizeof(struct filecopy_options));
	if (retval) {
		memcpy(retval, &options_default, sizeof(options_default));
	}
	return retval;
}

void
filecopy_options_release(filecopy_options_t o)
{
	struct filecopy_options *opts = (void*)o;

#ifdef __BLOCKS__
	if (opts->status_b)
		Block_release(opts->status_b);
	if (opts->error_b)
		Block_release(opts->error_b);
#endif /* __BLOCKS__ */
	free(opts);
}

int
filecopy_set_int(filecopy_options_t o, const char *opt, int v)
{
	return EINVAL;
}
	
int
filecopy_set_bool(filecopy_options_t o, const char *opt, int v)
{
	struct filecopy_options *opts = (void*)o;

	if (fc_option_data == opt) {
		opts->data = v;
	} else if (fc_option_xattr == opt) {
		opts->xattr = v;
	} else if (fc_option_acl == opt) {
		opts->acl = v;
	} else if (fc_option_perms == opt) {
		opts->posix = v;
	} else if (fc_option_times == opt) {
		opts->times = v;
	} else if (fc_option_recursion == opt) {
		opts->recursion = v;
	} else if (fc_option_follow == opt) {
		opts->follow = v;
	} else if (fc_option_remove == opt) {
		opts->remove = v;
	} else {
		return EINVAL;
	}
	return 0;
}

int
filecopy_get_bool(filecopy_options_t o, const char *opt)
{
	struct filecopy_options *opts = (void*)o;

	if (fc_option_data == opt) {
		return opts->data;
	} else if (fc_option_xattr == opt) {
		return opts->xattr;
	} else if (fc_option_acl == opt) {
		return opts->acl;
	} else if (fc_option_perms == opt) {
		return opts->posix;
	} else if (fc_option_times == opt) {
		return opts->times;
	} else if (fc_option_recursion == opt) {
		return opts->recursion;
	} else if (fc_option_follow == opt) {
		return opts->follow;
	} else if (fc_option_remove == opt) {
		return opts->remove;
	} else {
		errno = EINVAL;
		return -1;
	}
	return 0;
	
}

int
filecopy_set_string(filecopy_options_t o, const char *opt, const char *v)
{
	return EINVAL;
}

static acl_t
uberacl(int type)
{
	acl_t acl = acl_init(1);
	acl_permset_t perms;
	acl_entry_t first = NULL;
	uid_t me = geteuid();
	
	if (acl == NULL) {
		warn("Unable to create uberace");
		return NULL;
	}

	if (acl_create_entry_np(&acl, &first, ACL_FIRST_ENTRY) == -1) {
		warn("Unable to create magic first ACE");
		acl_free(acl);
		return NULL;
	}
	if (acl_get_permset(first, &perms) == -1) {
		warn("Unable to get permset from magic first ACE");
		acl_free(acl);
		return NULL;
	}
	acl_clear_perms(perms);

	// Now we need to know what type to use.
	if (type == ACL_TYPE_ACCESS) {
		// Simple POSIX ACL
		// So we just need to use write and search
		acl_add_perm(perms, ACL_WRITE);
		acl_add_perm(perms, ACL_EXECUTE);	// In case it's a directory
	} else if (type == ACL_TYPE_NFS4) {
		int kr;
		acl_add_perm(perms, ACL_WRITE_DATA);
		acl_add_perm(perms, ACL_ADD_FILE);
		acl_add_perm(perms, ACL_APPEND_DATA);
		acl_add_perm(perms, ACL_WRITE_ATTRIBUTES);
		acl_add_perm(perms, ACL_WRITE_ACL);
		acl_add_perm(perms, ACL_WRITE_NAMED_ATTRS);
		acl_add_perm(perms, ACL_READ_ACL);
		kr = acl_set_entry_type_np(first, ACL_ENTRY_TYPE_ALLOW);
		if (kr == -1) {
			warn("could not set ACL type");
			acl_free(acl);
			return NULL;
		}
	}
	if (acl_set_permset(first, perms) == -1)
		warn("Could not set permset into ACE");

	if (acl_set_tag_type(first, ACL_USER) == -1)
		warn("Coudl not set ACE tag type");
	
	if (acl_set_qualifier(first, &me) == -1) {
		warn("Could not set ACE qualifier");
	}
	return acl;
}

static int
create_dst(const char *file)
{
	return 0;
}

#ifdef __BLOCKS__
static int
iterate_xattrs(int fd,
	       int ns,
	       int (^handler)(const char *eaname))
{
	ssize_t kr;
	int retval = 0;
	
	kr = extattr_list_fd(fd, ns, NULL, 0);
	if (kr == -1) {
		return kr;
	}
	if (kr > 0) {
		char *buffer;
		size_t bufsize = kr;
		struct eanamebuf {
			unsigned char len;
			unsigned char name[];
		} *bufptr;
		
		buffer = malloc(bufsize);
		if (buffer == NULL)
			return -1;
		
		kr = extattr_list_fd(fd, ns, buffer, bufsize);
		if (kr == -1) {
			free(buffer);
			return kr;
		}
		for (bufptr = (void*)buffer;
		     (void*)bufptr < (void*)(buffer + bufsize);
		     bufptr = (void*)((char*)bufptr + bufptr->len + 1)) {
			char eaname[bufptr->len + 1];
			strlcpy(eaname, (const char*)bufptr->name, sizeof(eaname));
			if (handler(eaname) == -1) {
				retval = -1;
				break;
			}
		}
		free(buffer);
	}
	return retval;
}
#else
# error "Need blocks to work"
// Seriously, doing that with function pointers is obnoxious
#endif
/*
 * Implement the EA copying.
 * This first attempts to remove all the EAs on the destination.
 * If this doesn't succeed, it's not a failure, however.
 *
 * This will attempt to get "SYSTEM" EAs first; if that failes with
 * EPERM, it is ignored.
 *
 * For each EA it finds, it will call the filter function/block if
 * that is defined; this can either skip, abort, or continue.
 * Abort means that the function exits with an error.
 *
 * For each EA that is copied, if there is an error, the EA error
 * function/callback will be invoked, and can also skip, abort, or
 * or continue.  skip and continue are the same, in this context.
 */
static int
filecopy_xattrs(struct filecopy_options *opts)
{
	int src_fd = opts->src.fd;
	int dst_fd = opts->dst.fd;
	filecopy_status_t cb_status;
	
	int retval = 0;
	char *buffer = NULL;
	size_t bufsize;
	struct ea_ns {
		int ns_id;
		const char *ns_name;
		int perm_req;
	} namespaces[] = {
		{ EXTATTR_NAMESPACE_SYSTEM, EXTATTR_NAMESPACE_SYSTEM_STRING, 1 },
		{ EXTATTR_NAMESPACE_USER, EXTATTR_NAMESPACE_USER_STRING, 0 },
		{ 0 },
	}, *ptr;
	
	if (opts->statuscb) {
		cb_status = (opts->statuscb)(fc_status_extattr_start,
					     opts->context,
					     opts->src.name);
	} else if (opts->status_b) {
		cb_status = (opts->status_b)(fc_status_extattr_start, opts->src.name);
	} else {
		cb_status = FC_CONTINUE;
	}
	if (cb_status == FC_ABORT) {
		errno = 0;
		return -1;
	} else if (cb_status == FC_SKIP) {
		// Don't know why you'd do this
		errno = 0;
		return 0;
	}

	// Remove all EAs from the destination
	for (ptr = namespaces; ptr->ns_name; ptr++) {
		int kr;
		
		(void)iterate_xattrs(dst_fd,
				     ptr->ns_id,
				     ^(const char *eaname) {
					     int status = extattr_delete_fd(dst_fd, ptr->ns_id, eaname);
					     if (status == -1) {
						     warn("Could not delete EA %s:%s from %s", ptr->ns_name, eaname, opts->dst.name);
						     return status;
					     }
					     return 0;
				     });
	}
	// Now we copy from src to dst!  Easy as pie!
	for (ptr = namespaces; ptr->ns_name; ptr++) {
		int kr;

		kr = iterate_xattrs(src_fd, ptr->ns_id, ^(const char *eaname) {
				ssize_t bufsize;
				filecopy_status_t fstatus = FC_CONTINUE;
				int retval;
				
				if (opts->statuscb) {
					fstatus = (opts->statuscb)(fc_status_extattr,
								    opts->context,
								    opts->src.name,
								    ptr->ns_name,
								    eaname);
				} else if (opts->status_b) {
					fstatus = (opts->status_b)(fc_status_extattr,
								    opts->src.name,
								    ptr->ns_name,
								    eaname);
				} else {
					fstatus = FC_CONTINUE;
				}
				switch (fstatus) {
				default:
				case FC_ABORT:
					errno = 0;
					return -1;
				case FC_SKIP:
					return 0;	// Return from the block
				case FC_CONTINUE:
					break;
				}
				
				bufsize = extattr_get_fd(src_fd, ptr->ns_id, eaname, NULL, 0);
#define CHECK_ERROR(cb, b) {						\
					filecopy_status_t estatus;	\
					if (cb) { \
						estatus = (cb)(fc_error_extattr, \
							       opts->context, \
							       ptr->ns_name, \
							       ptr->ns_name, \
							       eaname,	\
							       errno);	\
					} else if (b) {			\
						estatus = (b)(fc_error_extattr, \
							      opts->src.name, \
							      ptr->ns_name, \
							      eaname,	\
							      errno);	\
					} else				\
						estatus = FC_ABORT;	\
					switch (estatus) {		\
					default:			\
					case FC_ABORT:			\
						return -1;		\
					case FC_SKIP:			\
						return 0;		\
					case FC_CONTINUE:		\
						break;			\
					}				\
				}
				if (bufsize == -1) {
					CHECK_ERROR(opts->errorcb, opts->error_b);
				} else if (bufsize > 0) {
					int retval;
					char *buffer = malloc(bufsize);
					if (buffer == NULL) {
						return -1;
					} else {
						int status;

						status  = extattr_get_fd(src_fd, ptr->ns_id, eaname, buffer, bufsize);
						if (status == -1) {
							CHECK_ERROR(opts->errorcb, opts->error_b);
						} else {
							status = extattr_set_fd(dst_fd, ptr->ns_id, eaname, buffer, bufsize);
							if (status == -1)
								retval = -1;
						}
						free(buffer);
					}
					return retval;
				}
			done:
				return retval;
			});
#undef CHECK_ERROR
		
		if (kr == -1) {
			if (errno == EPERM && ptr->perm_req)
				continue;
			if (errno == ENOATTR) {
				// This means an EA disappeared.  Sorry, but not an error.
				continue;
			}
			retval = -1;
			break;
		}
	}
	return retval;
}

/*
 * Open the destination.  This is considerably trickier than
 * opening the source, because we have to set flags, and check
 * filesystem object types, depending on the options.
 * Beause of that, we may end up having to attempt to open it
 * multiple times.
 *
 * Note that the goal of this function is to end up with
 * the destination open, period.  For writing if possible, but
 * just open otherise.
 */
static int
open_dest(struct filecopy_options *opts, const char *name)
{
	int oflags;
	int tmpfd;
	int kr;
	struct stat sbuf;

	if (opts->remove) {
		(void)remove(name);
	}
	if (opts->data) {
		oflags = O_RDWR | O_CREAT | O_TRUNC;
	} else {
		// Has to be writable for setting EAs on a file
		oflags = O_RDWR;
	}
	kr = (opts->follow ? stat : lstat)(name, &sbuf);
	if (kr == -1) {
		// It doesn't exist, so we need to create it.
			switch (opts->src.type) {
		case TYPE_FILE:
			tmpfd = open(name, oflags, (opts->src.sbuf.st_mode & ~S_IFMT) | S_IRWXU);
			if (tmpfd != -1) {
				opts->dst.flags |= FLAG_CREATED;	// We created it, so we clean up on error
			}
			break;
		case TYPE_DIR:
			kr = mkdir(name, (opts->src.sbuf.st_mode & ~S_IFMT) | S_IRWXU);
			if (kr == 0) {
				opts->dst.flags |= FLAG_CREATED;
				tmpfd = open(name, O_RDONLY | O_DIRECTORY);
			}
			break;
		case TYPE_LINK:
		{
			char slink_buf[opts->src.sbuf.st_size];
			kr = readlink(opts->src.name, slink_buf, sizeof(slink_buf));
			if (kr == -1) {
				return -1;
			}
			kr = symlink(slink_buf, name);
			if (kr == -1) {
				return -1;
			}
#ifdef O_SYMLINK
			opts->dst.fd = open(name, O_RDONLY | O_SYMLINK);
#endif
		}
			break;
		default:
			// Shouldn't get here due to earlier checks
			return -1;
		}
	} else {
		switch (opts->src.type) {
		case TYPE_FILE:
			tmpfd = open(name, oflags, (opts->src.sbuf.st_mode & ~S_IFMT) | S_IRWXU);
			break;
		case TYPE_DIR:
			tmpfd = open(name, O_RDONLY | O_DIRECTORY);
			break;
		case TYPE_LINK:
#ifdef O_SYMLINK
			tmpfd = open(name, O_RDONLY | O_SYMLINK);
#endif
			break;
		default:
			return -1;
		}
	}

	if (tmpfd == -1) {
		// We failed to get an open file descriptor
		// But this is okay if it's a symlink
		if (opts->src.type == TYPE_LINK) {
			// If we made it here, we created teh destination.
			lstat(name, &opts->dst.sbuf);
		} else {
			goto fail;
		} 
	} else {
		fstat(tmpfd, &opts->dst.sbuf);
		opts->dst.fd = tmpfd;
	}
	switch (opts->dst.sbuf.st_mode & S_IFMT) {
	case S_IFREG:
		opts->dst.type = TYPE_FILE; break;
	case S_IFDIR:
		opts->dst.type = TYPE_DIR; break;
	case S_IFLNK:
		opts->dst.type = TYPE_LINK; break;
	default:
		// Don't know what, so it's a failure
		goto fail;
	}
	opts->dst.name = name;
	
	return 0;
fail:
	// do cleanup
	if (opts->dst.flags & FLAG_CREATED) {
		(void)remove(name);
	}
	return -1;
}

static int
open_source(struct filecopy_options *opts, const char *name)
{
	int kr;
	
	opts->src.name = name;
	kr = (opts->follow ? stat : lstat)(name, &opts->src.sbuf);
	if (kr == 0) {
		int o_flags = O_RDONLY;
		switch (opts->src.sbuf.st_mode & S_IFMT) {
		case S_IFREG:	opts->src.type = TYPE_FILE; break;
		case S_IFDIR:	opts->src.type = TYPE_DIR; break;
		case S_IFLNK:	opts->src.type = TYPE_LINK; break;
		default:
			errno = EINVAL;
			return -1;
		}
		if (opts->src.type == TYPE_LINK) {
			o_flags |= O_NOFOLLOW;
		}
		opts->src.fd = open(name, o_flags);
		return opts->src.fd == -1 ? -1 : 0;
	} else {
		return -1;
	}
}

static void
close_files(struct filecopy_options *opts)
{
	if (opts->src.fd != -1) {
		close(opts->src.fd);
	}
	if (opts->dst.fd != -1) {
		close(opts->dst.fd);
	}
	return;
}

/*
 * Copy src -> dst
 * 
 */
int
filecopy(filecopy_options_t o, const char *src, const char *dst)
{
	struct stat s_buf, d_buf;
	acl_t orig_dst_acl = NULL;
	struct filecopy_options *opts = (void*)o;
	int dst_exists = 0;
	int src_fd, dst_fd;
	int o_flags = 0;
	char *data_buffer = NULL;
	static const size_t kBufferSize = 1024 * 1024;
	int terror = 0;
	int retval = 0;
	
	if (opts == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (opts->data) {
		data_buffer = malloc(kBufferSize);
		if (data_buffer == NULL) {
			terror = ENOMEM;
			goto done;
		}
	}
	
	if (open_source(opts, src) == -1) {
		terror = errno;
		goto done;
	}
	if (open_dest(opts, dst) == -1) {
		terror = errno;
		goto done;
	}
	/*
	 * Now we need to see if the copy is something we can do.
	 * If we're copying data, we can only copy directory -> directory,
	 * symlink -> symlink, and file -> file.  If we're copying
	 * metadata, we can do any combination.
	 */
	if (opts->data) {
		if (opts->src.type != opts->dst.type) {
			terror = EINVAL;
			goto done;
		}
	}
	
#if 0
	int nfs4;
	int acl_type;
	acl_t new_dst_acl;
	nfs4 = (opts->follow ? pathconf : lpathconf)(dst, _PC_ACL_NFS4);
	acl_type = (nfs4 == 1) ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	orig_dst_acl = (opts->follow ? acl_get_file : acl_get_link_np)(dst, acl_type);
	new_dst_acl = uberacl(acl_type);
	if (new_dst_acl) {
		int kr;
		int brand = 0;
		if (acl_get_brand_np(new_dst_acl, &brand) == -1) {
			warn("Cannot get acl brand?");
		} else {
			warnx("ACL brand = %d", brand);
		}
		char *t = acl_to_text(new_dst_acl, NULL);
		fprintf(stderr, "acl = %s\n", t);
		kr = (opts->follow ? acl_set_file : acl_set_link_np)(dst, acl_type, new_dst_acl);
		if (kr == -1) {
			char *txt = acl_to_text_np(new_dst_acl, NULL, ACL_TEXT_VERBOSE | ACL_TEXT_APPEND_ID);
			warn("Could not create ACL %s on dst %s", txt, dst);
			acl_free((void*)txt);
			acl_free(new_dst_acl);
		}
	}
#endif
	
	/*
	 * Copy EAs, if requested
	 */
	if (opts->xattr) {
		int kr = filecopy_xattrs(opts);
		if (kr == -1) {
			terror = errno;
			warn("Could not copy xattrs");
			goto done;
		}
	}
	/*
	 * Next, copy data if requested.
	 * We only copy data for regular files.  Symlinks
	 * are created as a copy, and directories only get
	 * metadata copied.
	 */
	if (opts->data && opts->src.type == TYPE_FILE) {
		ssize_t nr, nw;
		off_t total = 0;

		while ((nr = read(opts->src.fd, data_buffer, kBufferSize)) > 0) {
			total += nr;
			nw = write(opts->dst.fd, data_buffer, nr);
			if (nw == -1) {
				terror = errno;
				warn("Could not write data");
				goto done;
			}
		}
		if (nr == -1) {
			terror = errno;
			warn("Could not read data");
			goto done;
		}
	}

done:
	if (data_buffer)
		free(data_buffer);
	close_files(opts);
	if (terror) {	// Indicates an error
		if (opts->dst.flags & FLAG_CREATED)
			(void)remove(dst);
		errno = terror;
		retval = -1;
	}
	return retval;
}
