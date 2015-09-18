#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <time.h>

#ifdef __BLOCKS__
# include <Block.h>
#endif
#include <errno.h>

#include <sys/stat.h>
#include <sys/extattr.h>
#include <sys/acl.h>

#include "filecopy.h"

#define DEBUG_DEVEL 0	// Turn to 1 for development debugging

#define FLAG_CREATED	0x00001

typedef enum {
	TYPE_UNKNOWN = 0,
	TYPE_DIR,
	TYPE_FILE,
	TYPE_LINK,
} ftype_t;

struct xattr_ns {
	int ns_id;
	const char *ns_name;
	int perm_req;
};

struct file_state {
	const char *name;
	struct stat sbuf;
	ftype_t type;
	int flags;
	int fd;
	acl_t acl;
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
	// The following are used for context during operations
	struct file_state src;
	struct file_state dst;
	size_t bufsize;
	char *buffer;
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

static struct xattr_ns
namespaces[] = {
	{ EXTATTR_NAMESPACE_SYSTEM, EXTATTR_NAMESPACE_SYSTEM_STRING, 1 },
	{ EXTATTR_NAMESPACE_USER, EXTATTR_NAMESPACE_USER_STRING, 0 },
	{ 0 },
};

//#define DECL(name) const char *name __attribute__((section(".rodata"))) = #name
#define DECL(name) const char *const name = #name
DECL(fc_option_data);
DECL(fc_option_xattr);
DECL(fc_option_acl);
DECL(fc_option_perms);
DECL(fc_option_times);
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

int
filecopy_set_option(filecopy_options_t o, const char *opt, ...)
{
	struct filecopy_options *opts = (void*)o;
	va_list ap;
	const char *optname;
	int rv = 0;
	
	va_start(ap, opt);

	while ((optname = va_arg(ap, const char *)) != NULL) {
		if (optname == fc_option_data ||
		    optname == fc_option_xattr ||
		    optname == fc_option_acl ||
		    optname == fc_option_perms ||
		    optname == fc_option_times ||
		    optname == fc_option_follow ||
		    optname == fc_option_exclusive) {
			rv = filecopy_set_bool(opts, optname, va_arg(ap, int));
		} else if (optname == fc_option_context) {
			opts->context = va_arg(ap, void *);
			rv = 0;
		} else if (optname == fc_option_status_cb ||
			   optname == fc_option_error_cb) {
			rv = filecopy_set_callback(opts, optname, va_arg(ap, filecopy_callback_t));
		} else if (optname == fc_option_status_block ||
			   optname == fc_option_error_block) {
			rv = filecopy_set_block(opts, optname, va_arg(ap, filecopy_block_t));
		} else {
			rv = EINVAL;
		}
		if (rv != 0)
			break;
	}
	return rv;
}

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
	if (opts->src.acl)
		acl_free(opts->src.acl);
	if (opts->dst.acl)
		acl_free(opts->dst.acl);
	
	free(opts);
}

int
filecopy_set_callback(filecopy_options_t o, const char *opt, filecopy_callback_t cb)
{
	struct filecopy_options *opts = (void*)o;
	if (opt == fc_option_status_cb) {
		opts->statuscb = cb;
		if (opts->status_b) {
			Block_release(opts->status_b);
			opts->status_b = NULL;
		}
	} else if (opt == fc_option_error_cb) {
		opts->errorcb = cb;
		if (opts->error_b) {
			Block_release(opts->error_b);
			opts->error_b = NULL;
		}
	} else {
		return EINVAL;
	}
	return 0;
}

#ifdef __BLOCKS__
int
filecopy_set_block(filecopy_options_t o, const char *opt, filecopy_block_t b)
{
	struct filecopy_options *opts = (void*)o;
	if (opt == fc_option_status_block) {
		opts->status_b = Block_copy(b);
		opts->statuscb = NULL;
	} else if (opt == fc_option_error_block) {
		opts->error_b = Block_copy(b);
		opts->errorcb = NULL;
	} else
		return EINVAL;
	return 0;
}
#endif

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
/*
 * Return the type of ACL -- ACL_TYPE_ACCESS or ACL_TYPE_NFS4 --
 * for the given file.  This assumes the file exists.
 */
static int
get_acl_type(struct file_state *state)
{
	int acl_type;
#ifndef O_SYMLINK
	if (state->type == TYPE_LINK)
		acl_type = lpathconf(state->name, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	else
#endif
		acl_type = fpathconf(state->fd, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	return acl_type;
}

/*
 * Determine if the ACL has an uberace.
 * This will by definition be the first ACE.
 * We need to know the branding; if there's no branding
 * then we return 0.
 * If we decide it does have the uberace, then
 * we return 1.
 */
static int
has_uberace(acl_t acl)
{
	int retval = 0;
	int acl_type;
	acl_permset_t perms;
	acl_entry_t first = NULL;
	uid_t me = geteuid();
	uid_t *q;
	acl_tag_t tag;
	
	if (acl) {
		if (acl_get_brand_np(acl, &acl_type) == -1)
			goto done;
		
		switch (acl_type) {
		case ACL_BRAND_POSIX:	acl_type = ACL_TYPE_ACCESS; break;
		case ACL_BRAND_NFS4:	acl_type = ACL_TYPE_NFS4; break;
		default:	goto done;
		}

		if (acl_get_entry(acl, ACL_FIRST_ENTRY, &first) == -1) {
			// Can't get the first ACE, so bail out
			goto done;
		}

		if (acl_get_tag_type(first, &tag) == -1) {
			goto done;
		}
		
		if (tag != ACL_USER) {
			// Not the uberace we constructed!
			goto done;
		}
		
		if ((q = acl_get_qualifier(first)) == NULL) {
			goto done;
		}
		if (*q != me) {
			goto done;
		}
		
		// All that's left is comparing the permision set
		if (acl_get_permset(first, &perms) == -1) {
			// Another chance to bail
			goto done;
		}
		if (acl_type == ACL_TYPE_ACCESS) {
			if (acl_get_perm_np(perms, ACL_WRITE) != 1 ||
			    acl_get_perm_np(perms, ACL_EXECUTE) != 1 ||
			    acl_get_perm_np(perms, ACL_READ) != 0)
				goto done;
			retval = 1;
		} else if (acl_type == ACL_TYPE_NFS4) {
			acl_entry_type_t type;

			if (acl_get_entry_type_np(first, &type) == -1) {
				goto done;
			}
			if (type != ACL_ENTRY_TYPE_ALLOW) {
				goto done;
			}
			if (acl_get_perm_np(perms, ACL_WRITE_DATA) != 1 ||
			    acl_get_perm_np(perms, ACL_ADD_FILE) != 1 ||
			    acl_get_perm_np(perms, ACL_APPEND_DATA) != 1 ||
			    acl_get_perm_np(perms, ACL_WRITE_ATTRIBUTES) != 1 ||
			    acl_get_perm_np(perms, ACL_WRITE_ACL) != 1 ||
			    acl_get_perm_np(perms, ACL_WRITE_NAMED_ATTRS) != 1)
				goto done;
			retval = 1;
		} else {
			abort();
		}
	}
done:
	return retval;
}

static int
add_uberace(acl_t *aclp)
{
	int acl_type;
	acl_permset_t perms;
	acl_entry_t first = NULL;
	uid_t me = geteuid();
	
	if (aclp == NULL || *aclp == NULL) {
		warn("Unable to create uberace");
		return EINVAL;
	}

	if (acl_get_brand_np(*aclp, &acl_type) == -1) {
		warn("Unable to get ACL brand");
		return errno;
	}
	
	switch (acl_type) {
	case ACL_BRAND_POSIX:	acl_type = ACL_TYPE_ACCESS; break;
	case ACL_BRAND_NFS4:	acl_type = ACL_TYPE_NFS4; break;
	default:
		errno = EINVAL;
		return errno;
	}
			
	if (acl_create_entry_np(aclp, &first, ACL_FIRST_ENTRY) == -1) {
		warn("Unable to create magic first ACE");
		return errno;
	}
	if (acl_get_permset(first, &perms) == -1) {
		warn("Unable to get permset from magic first ACE");
		return errno;
	}
	acl_clear_perms(perms);

	// Now we need to know what type to use.
	if (acl_type == ACL_TYPE_ACCESS) {
		// Simple POSIX ACL
		// So we just need to use write and search
		acl_add_perm(perms, ACL_WRITE);
		acl_add_perm(perms, ACL_EXECUTE);	// In case it's a directory
	} else if (acl_type == ACL_TYPE_NFS4) {
		int kr;
		acl_add_perm(perms, ACL_WRITE_DATA);
		acl_add_perm(perms, ACL_ADD_FILE);
		acl_add_perm(perms, ACL_APPEND_DATA);
		acl_add_perm(perms, ACL_WRITE_ATTRIBUTES);
		acl_add_perm(perms, ACL_WRITE_ACL);
		acl_add_perm(perms, ACL_WRITE_NAMED_ATTRS);
		kr = acl_set_entry_type_np(first, ACL_ENTRY_TYPE_ALLOW);
		if (kr == -1) {
			warn("could not set ACL type");
			return errno;
		}
	}
	if (acl_set_permset(first, perms) == -1)
		warn("Could not set permset into ACE");

	if (acl_set_tag_type(first, ACL_USER) == -1)
		warn("Coudl not set ACE tag type");
	
	if (acl_set_qualifier(first, &me) == -1) {
		warn("Could not set ACE qualifier");
	}
	return 0;
}

/*
 * Add an uber-ace to the given file.
 * The uber-ace gives us all the write permissions we could
 * ever want.
 */
static int
set_uberacl(struct file_state *state)
{
	int acl_type;
	acl_t acl;
	int kr;
	
	acl_type = get_acl_type(state);

	if (state->acl == NULL) {
		acl = acl_init(1);
	} else {
		acl = acl_dup(state->acl);
	}
	if (acl == NULL) {
		warn("Could not create ACL copy");
		return errno;
	}

	kr = add_uberace(&acl);
	if (kr == 0) {
#ifndef O_SYMLINK
		if (state->type == TYPE_LINK)
			kr = acl_set_link_np(state->name, acl_type, acl);
		else
#endif
			kr = acl_set_fd_np(state->fd, acl, acl_type);
		acl_free(acl);
	} else {
		kr = -1;
	}
	return kr;
}

static acl_t
get_acl(struct file_state *state)
{
	int nfs4;
	int acl_type;
	acl_t retval = NULL;
	
	acl_type = get_acl_type(state);

#ifndef O_SYMLINK
	if (state->type == TYPE_LINK)
		retval = acl_get_link_np(state->name, acl_type);
	else
#endif
		retval = acl_get_fd_np(state->fd, acl_type);
	return retval;
}


/*
 * Attempt to reove the uberace from the given file.
 * If the file doesn't have an ACL, we don't care;
 * if the first ACE isn't the uberace, we don't care.
 */
static filecopy_status_t
remove_uberace(struct file_state *state)
{
	acl_t file_acl = NULL;
	int acl_type = get_acl_type(state);
	filecopy_status_t retval = FC_ABORT;
	int kr;
	
#ifndef O_SYMLINK
	if (state->type == TYPE_LINK)
		file_acl = acl_get_link_np(state->name, acl_type);
	else
#endif
		file_acl = acl_get_fd_np(state->fd, acl_type);

	if (file_acl == NULL) {
		// No acl!
		retval =  FC_CONTINUE;
		goto done;
	}
	if (has_uberace(file_acl) == 0) {
		// No uberace!
		retval = FC_CONTINUE;
		goto done;
	}
	// At this point, we know that file_acl has an uberace as
	// the first entry.  So we simply delete it.
	if (acl_delete_entry_np(file_acl, ACL_FIRST_ENTRY) == -1) {
		warn("Could not delete uberace from ACL");
		goto done;
	}
#ifndef O_SYMLINK
	if (state->type == TYPE_LINK)
		kr = acl_set_link_np(state->name, acl_type, file_acl);
	else
#endif
		kr = acl_set_fd_np(state->fd, file_acl, acl_type);
	if (kr == -1) {
		warn("Could not apply de-uberaced ACL to file");
		retval = FC_ABORT;
	}
	retval = FC_CONTINUE;
done:
	if (file_acl)
		acl_free(file_acl);
	
	return retval;
}

static filecopy_status_t
copy_acl(struct filecopy_options *opts)
{
	filecopy_status_t retval = FC_CONTINUE;
	acl_t src_acl, dst_acl;
	acl_t new_acl = NULL;
	acl_entry_t ace;
	int ace_id;
	size_t ace_index = 0;
	int acl_type = 0;
	
	src_acl = opts->src.acl;
	dst_acl = opts->dst.acl;
	
	if (src_acl == NULL && dst_acl == NULL)
		goto done;
	
#if DEBUG_DEVEL
	if (dst_acl)
		warnx("dst_acl = %s", acl_to_text(dst_acl, NULL));
#endif
	
	// Need to figure out what kind of ACL to use.
#ifdef O_SYMLINK
	if (opts->dst.type == TYPE_LINK)
		acl_type = lpathconf(opts->dst.name, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	else
#endif
		acl_type = fpathconf(opts->dst.fd, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	new_acl = acl_init(1);

	if (new_acl == NULL) {
		retval = FC_ABORT;
		goto done;
	}
	
	/*
	 * The purpose of this block is to to through the ACL on
	 * the source, and add entries to the new ACL.
	 * If ACL_ENTRY_INHERITED is exposed, we'll skip those entries.
	 */
	/*
	 * XXX note about copying ACL entries:  we support two kinds,
	 * POSIX and NFSv4. I am doing no translation between them, which
	 * I suspect means problems when copying between filesystems.
	 * Investigate this.
	 */
	if (src_acl) {
#if DEBUG_DEVEL
		warnx("source acl = \n%s", acl_to_text(src_acl, NULL));
#endif
		for (ace_id = ACL_FIRST_ENTRY;
		     acl_get_entry(src_acl, ace_id, &ace) == 1;
		     ace_id = ACL_NEXT_ENTRY) {
			acl_entry_t tmp;
			acl_tag_t tag;
#ifdef ACL_ENTRY_INHERITED
			acl_flagset_t flags;
			if (acl_get_flagset_np(ace, &flags) != -1)
				if (acl_get_flag_np(flags, ACL_ENTRY_INHERITED) == 0)
#endif
				{
					// Note how I'm cleverly not checking for errors
					acl_create_entry_np(&new_acl, &tmp, ace_index++);
					/*
					 * You'd think that acl_copy_entry() would do everything we want...
					 * but it doesn't:  if we don't set the tag type, it doesn't seem
					 * to get branded, and things simply do not work.
					 */
					acl_get_tag_type(ace, &tag);
					acl_set_tag_type(tmp, tag);
					acl_copy_entry(tmp, ace);
#if DEBUG_DEVEL
					warnx("ace_index = %zd:  Now tmp acl = \n%s", ace_index - 1, acl_to_text(new_acl, NULL));
#endif
				}
		}
	}
#ifdef ACL_ENTRY_INHERITED
	/*
	 * The purpose of this block is to go through the ACL on
	 * the destination, and add on the inherited entries.
	 * This is only possible if ACL_ENTRY_INHERITED is exposed.
	 */
	if (dst_acl) {
		for (ace_id = ACL_FIRST_ENTRY;
		     acl_get_entry(dst_acl, ace_id, &ace) == 1;
		     ace_id = ACL_NEXT_ENTRY) {
			acl_flagset_t flags;
			if (acl_get_flagset_np(ace, &flags) != -1) {
				if (acl_get_flag_np(flags, ACL_ENTRY_INHERITED) == 1) {
					acl_entry_t tmp;
					acl_tag_t tag;
					acl_create_entry_np(&new_acl, &tmp, ace_index++);
#if DEBUG_DEVEL
					warnx("Found an inherited ACE");
#endif
					acl_get_tag_type(ace, &tag);
					acl_set_tag_type(tmp, tag);
					acl_copy_entry(tmp, ace);
				}
			}
		}
	}
	
#endif
done:
	/*
	 * This section does two things:
	 * It removes the ACL from the destination if there is nothing to
	 * apply, otherwise, it applies the ACL.
	 */
	if (dst_acl == NULL || ace_index == 0) {
		/*
		 * The file didn't have an ACL.
		 * I truly don't know what to do here -- if it has
		 * an ACL now, I'm not sure how I would get rid of
		 * anything.  
		 *
		 * Looks like what we have to do is get the ACL, strip it,
		 * and then set it.
		 */
		if (dst_acl)
			acl_free(dst_acl);
		opts->dst.acl = NULL;
#ifndef O_SYMLINK
		if (opts->dst.type == TYPE_LINK)
			acl_type = lpathconf(opts->dst.name, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_BRAND_POSIX;
		else
#endif
			acl_type = fpathconf(opts->dst.fd, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_BRAND_POSIX;

#ifndef O_SYMLINK
		if (opts->dst.type == TYPE_LINK)
			dst_acl = acl_get_link_np(opts->dst.name, acl_type);
		else
#endif
			dst_acl = acl_get_fd_np(opts->dst.fd, acl_type);

		if (dst_acl) {
			int kr;
			acl_t tmp_acl = acl_strip_np(dst_acl, 1);	// What if it's 0?
			if (tmp_acl) {
#ifndef O_SYMLINK
				if (opts->dst.type == TYPE_LINK)
					kr = acl_set_link_np(opts->dst.name, acl_type, tmp_acl);
				else
#endif
					kr = acl_set_fd_np(opts->dst.fd, tmp_acl, acl_type);
				acl_free(tmp_acl);
			}
			acl_free(dst_acl);
		}
	} else if (ace_index > 0) {
		// There are actually some ACLs
		int nfs4;
		int kr;
		
		kr = acl_get_brand_np(new_acl, &acl_type);
		if (kr == -1 || acl_type == ACL_BRAND_UNKNOWN) {
			warn("Could not get new ACL type, can't do much else");
			retval = FC_ABORT;
		} else {
			acl_type = acl_type == ACL_BRAND_NFS4 ? ACL_TYPE_NFS4 : ACL_BRAND_POSIX;
#ifndef O_SYMLINK
			if (opts->dst.type == TYPE_LINK)
				kr = acl_set_link_np(opts->dst.name, acl_type, new_acl);
			else
#endif
				kr = acl_set_fd_np(opts->dst.fd, new_acl, acl_type);
			if (kr == -1) {
				warn("Could not set new ACL on destination");
				retval = FC_ABORT;
			}
		}
	}
	if (new_acl)
		acl_free(new_acl);
	
	return retval;
}

static int
create_dst(const char *file)
{
	return 0;
}

#ifdef __BLOCKS__
static filecopy_status_t
iterate_xattrs(struct file_state *state,
	       int ns,
	       filecopy_status_t (^handler)(const char *eaname))
{
	ssize_t kr;
	filecopy_status_t retval = FC_CONTINUE;
	
#ifndef O_SYMLINK
	if (state->type == TYPE_LINK)
		kr = extattr_list_link(state->name, ns, NULL, 0);
	else
#endif
		kr = extattr_list_fd(state->fd, ns, NULL, 0);
	if (kr == -1) {
		return FC_ABORT;
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
			return FC_ABORT;
		
#ifndef O_SYMLINK
		if (state->type == TYPE_LINK)
			kr = extattr_list_link(state->name, ns, buffer, bufsize);
		else
#endif
			kr = extattr_list_fd(state->fd, ns, buffer, bufsize);
		if (kr == -1) {
			free(buffer);
			return FC_ABORT;
		}
		for (bufptr = (void*)buffer;
		     (void*)bufptr < (void*)(buffer + bufsize);
		     bufptr = (void*)((char*)bufptr + bufptr->len + 1)) {
			char eaname[bufptr->len + 1];
			strlcpy(eaname, (const char*)bufptr->name, sizeof(eaname));
			retval = handler(eaname);
			if (retval == FC_ABORT || retval == FC_SKIP) {
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
 * Helper functions for xattr copying.
 * If an error occurs, the error handler is called.
 *
 * Notification of start and completion of
 * EA copying is handled outside these functions.
 */

/*
 * Get the named attribute from opts->src.
 * Calls the error handler when needed.
 * Return values:
 * FC_CONTINUE	- everything is good.
 * FC_SKIP	- Skip this EA, but no error.
 * FC_ABORT	- Stop copying, return an error.
 *
 * The caller is required to free() the allocated space.
 */

/*
 * Eror-handling for get_xattr:  if the error is EPERM,
 * the user is not root [fixme?], and the namespace is
 * allowed to return EPERM in those cases.  In that case
 * alone, the error handler is not invoked.
 */
static filecopy_status_t
get_xattr(struct filecopy_options *opts,
	  struct xattr_ns *namespace,
	  const char *attrname,
	  void **buffer,
	  size_t *length)
{
	void *ptr;
	ssize_t kr;

	/*
	 * We call the error handler, and not our caller.  This
	 * simplifies the caller's code a lot.
	 * We use a block because it's like a nested function.
	 */
	filecopy_status_t (^ehandler)(void) = ^(void) {
		filecopy_status_t tstatus = FC_ABORT;
		
		if (opts->errorcb)
			tstatus = (opts->errorcb)(fc_error_extattr,
						  opts->context,
						  namespace->ns_name,
						  attrname,
						  errno);
		else if (opts->error_b)
			tstatus = (opts->error_b)(fc_error_extattr,
						  namespace->ns_name,
						  attrname,
						  errno);
		switch (tstatus) {
		case FC_CONTINUE:
		case FC_SKIP:
			errno = 0;
		case FC_ABORT:
			break;
		default:
			errno = EINVAL;
			tstatus = FC_ABORT;
			break;
		}
		return tstatus;
	};
	if (buffer == NULL || length == NULL) {
		errno = EFAULT;
		return FC_ABORT;
	}

	/*
	 * First try to get the size of the buffer.
	 */
#ifndef O_SYMLINK
	if (opts->src.type == TYPE_LINK)
		kr = extattr_get_link(opts->src.name, namespace->ns_id, attrname, NULL, 0);
	else
#endif
		kr = extattr_get_fd(opts->src.fd, namespace->ns_id, attrname, NULL, 0);
	if (kr == -1) {
		// We only need to check for this here.
		if (errno == EPERM &&
		    namespace->perm_req &&
		    geteuid() == 0) {
			return FC_ABORT;
		}
		return (ehandler)();
	}

	ptr = malloc(kr);
	if (ptr == NULL) {
		return (ehandler)();
	}
	*length = kr;
	
#ifndef O_SYMLINK
	if (opts->src.type == TYPE_LINK)
		kr = extattr_get_link(opts->src.name, namespace->ns_id, attrname, ptr, *length);
	else
#endif
		kr = extattr_get_fd(opts->src.fd, namespace->ns_id, attrname, ptr, *length);
	if (kr == -1) {
		free(ptr);
		return (ehandler)();
	}
	*buffer = ptr;
	return FC_CONTINUE;
}

static filecopy_status_t
set_xattr(struct filecopy_options *opts,
	  struct xattr_ns *namespace,
	  const char *attrname,
	  void *buffer,
	  size_t length)
{
	ssize_t kr;
	/*
	 * We call the error handler, and not our caller.  This
	 * simplifies the caller's code a lot.
	 * We use a block because it's like a nested function.
	 */
	filecopy_status_t (^ehandler)(void) = ^(void) {
		filecopy_status_t tstatus = FC_ABORT;
		
		if (opts->errorcb)
			tstatus = (opts->errorcb)(fc_error_extattr,
						  opts->context,
						  namespace->ns_name,
						  attrname,
						  errno);
		else if (opts->error_b)
			tstatus = (opts->error_b)(fc_error_extattr,
						  namespace->ns_name,
						  attrname,
						  errno);
		switch (tstatus) {
		case FC_CONTINUE:
		case FC_SKIP:
			errno = 0;
		case FC_ABORT:
			break;
		default:
			errno = EINVAL;
			tstatus = FC_ABORT;
			break;
		}
		return tstatus;
	};

#ifndef O_SYMLINK
	if (opts->dst.type == TYPE_LINK)
		kr = extattr_set_link(opts->dst.name, namespace->ns_id, attrname, buffer, length);
	else
#endif
		kr = extattr_set_fd(opts->dst.fd, namespace->ns_id, attrname, buffer, length);

	if (kr == -1)
		return (ehandler)();
	return FC_CONTINUE;
}

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
static filecopy_status_t
copy_xattrs(struct filecopy_options *opts)
{
	int src_fd = opts->src.fd;
	int dst_fd = opts->dst.fd;
	filecopy_status_t cb_status;
	filecopy_status_t retval = FC_CONTINUE;
	char *buffer = NULL;
	size_t bufsize;
	struct xattr_ns *ptr;
	
	if (opts->statuscb) {
		cb_status = (opts->statuscb)(fc_status_extattr_start,
					     opts->context,
					     opts->src.name);
	} else if (opts->status_b) {
		cb_status = (opts->status_b)(fc_status_extattr_start, opts->src.name);
	} else {
		cb_status = FC_CONTINUE;
	}
	switch (cb_status) {
	case FC_ABORT:
	case FC_SKIP:
		errno = 0;
		return cb_status;
	default:
		errno = EINVAL;
		return FC_ABORT;
	case FC_CONTINUE:
		break;
	}

	// Remove all EAs from the destination
	for (ptr = namespaces; ptr->ns_name; ptr++) {
		int kr;
		
		(void)iterate_xattrs(&opts->dst,
				     ptr->ns_id,
				     ^(const char *eaname) {
					     int status;

#ifndef O_SYMLINK
					     if (opts->dst.type == TYPE_LINK)
						     status = extattr_delete_link(opts->dst.name,
										  ptr->ns_id,
										  eaname);
					     else
#endif
						     status = extattr_delete_fd(opts->dst.fd,
										ptr->ns_id,
										eaname);
					     if (status == -1) {
						     warn("Could not delete EA %s:%s from %s", ptr->ns_name, eaname, opts->dst.name);
						     return FC_ABORT;
					     }
					     return FC_CONTINUE;
				     });
	}
	// Now we copy from src to dst!  Easy as pie!
	for (ptr = namespaces; ptr->ns_name; ptr++) {
		retval = iterate_xattrs(&opts->src, ptr->ns_id, ^(const char *eaname) {
				filecopy_status_t fstatus = FC_CONTINUE;
				size_t bufsize;
				void *buffer = NULL;
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
					return fstatus;
				case FC_SKIP:
					return FC_SKIP;	// Return from the block
				case FC_CONTINUE:
					break;
				}
				
				fstatus = get_xattr(opts, ptr, eaname, &buffer, &bufsize);
				if (fstatus != FC_CONTINUE) {
					// get_exattr has already called the error handler
					return fstatus;
				}
				fstatus = set_xattr(opts, ptr, eaname, buffer, bufsize);
				free(buffer);
				return fstatus;
			});
		
		if (retval == FC_ABORT) {
			if (errno == EPERM && ptr->perm_req) {
				retval = FC_CONTINUE;
				continue;
			}
			if (errno == ENOATTR) {
				// This means an EA disappeared.  Sorry, but not an error.
				retval = FC_CONTINUE;
				continue;
			}
			break;
		}
	}
	if (retval == FC_CONTINUE) {
		if (opts->statuscb)
			retval = (opts->statuscb)(fc_status_extattr_completion,
						  opts->context,
						  NULL);
		else if (opts->status_b)
			retval = (opts->status_b)(fc_status_extattr_completion, NULL);
		switch (retval) {
		case FC_ABORT:
			errno = 0;
			break;
		case FC_SKIP:
		case FC_CONTINUE:
			break;
		default:
			errno = EINVAL;
			retval = FC_ABORT;
			break;
		}
	}
	return retval;
}
#if 0
acl_func() {
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
}
#endif

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
		if (opts->src.type == TYPE_LINK && errno == EMLINK) {
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
	opts->dst.acl = get_acl(&opts->dst);
	(void)set_uberacl(&opts->dst);
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
#ifdef O_SYMLINK
			o_flags |= O_SYMLINK;
#else
			opts->src.acl = get_acl(&opts->src);
#endif
		}
		opts->src.fd = open(name, o_flags);
		if (opts->src.fd != -1) {
			opts->src.acl = get_acl(&opts->src);
			return 0;
		} else {
#ifndef O_SYMLINK
			if (opts->src.type == TYPE_LINK && errno == EMLINK) {
				errno = 0;
				return 0;
			}
#endif
			return -1;
		}
	} else {
		return -1;
	}
}

static filecopy_status_t
copy_data(struct filecopy_options *opts)
{
	ssize_t nr, nw;
	off_t total = 0;
	int terror = 0;
	filecopy_status_t status = FC_CONTINUE;
	
	if (opts->statuscb)
		status = (opts->statuscb)(fc_status_data_start, opts->context);
	else if (opts->status_b)
		status = (opts->status_b)(fc_status_data_start);
	else
		status = FC_CONTINUE;
	switch (status) {
	case FC_ABORT:
		errno = 0;
		return status;
	default:
		errno = EINVAL;
		return FC_ABORT;
	case FC_SKIP:
		return FC_SKIP;
	case FC_CONTINUE:
		break;
	}
	
	while ((nr = read(opts->src.fd, opts->buffer, opts->bufsize)) > 0) {
		total += nr;
		if (opts->statuscb)
			status = (opts->statuscb)(fc_status_data_progress,
						  opts->context,
						  opts->src.sbuf.st_size,
						  total);
		else if (opts->status_b)
			status = (opts->status_b)(fc_status_data_progress,
						  opts->src.sbuf.st_size,
						  total);
		else
			status = FC_CONTINUE;
		switch (status) {
		case FC_ABORT:
		case FC_SKIP:
			errno = 0;
			goto done;
		default:
			errno = EINVAL;
			status = FC_ABORT;
			goto done;
		case FC_CONTINUE:
			break;
		}
		nw = write(opts->dst.fd, opts->buffer, nr);
		if (nw == -1) {
			terror = errno;
			warn("Could not write data");
			// Actually need to call the error handler here
			status = FC_ABORT;
			break;
		}
	}
	if (nr == -1) {
		terror = errno;
		// Actually need to call the error handler here
		status = FC_ABORT;
		warn("Could not read data");
	}
	if (status == FC_ABORT && terror != 0) {
		if (opts->errorcb)
			status = (opts->errorcb)(fc_error_data,
						 opts->context,
						 terror);
		else if (opts->error_b)
			status = (opts->error_b)(fc_error_data, terror);
		else
			status = FC_ABORT;

		switch (status) {
		case FC_ABORT:
			errno = terror;
			break;
		case FC_SKIP:
			errno = 0;
			break;
		case FC_CONTINUE:
			errno = 0;
			break;
		default:
			errno = EINVAL;
			status = FC_ABORT;
			break;
		}
	} else {
		if (opts->statuscb)
			status = (opts->statuscb)(fc_status_data_completion,
						  opts->context,
						  total);
		else if (opts->status_b)
			status = (opts->status_b)(fc_status_data_completion, total);
		else
			status = FC_CONTINUE;
		switch (status) {
		case FC_ABORT:
			errno = 0;
			break;
		default:
			errno = EINVAL;
			status = FC_ABORT;
			break;
		case FC_SKIP:
		case FC_CONTINUE:
			errno = 0;
			break;
		}
	}
done:
	return status;
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

static int
copy_posix(struct filecopy_options *opts)
{
#ifndef O_SYMLINK
	if (opts->dst.type == TYPE_LINK) {
		(void)lchmod(opts->dst.name, opts->src.sbuf.st_mode & ~S_IFMT);
		(void)lchown(opts->dst.name, opts->src.sbuf.st_uid, opts->src.sbuf.st_gid);
		(void)lchflags(opts->dst.name, opts->src.sbuf.st_flags);
	} else
#endif
	{
		(void)fchmod(opts->dst.fd, opts->src.sbuf.st_mode & ~S_IFMT);
		(void)fchown(opts->dst.fd, opts->src.sbuf.st_uid, opts->src.sbuf.st_gid);
		(void)fchflags(opts->dst.fd, opts->src.sbuf.st_flags);
	}
	return 0;
}

static int
copy_times(struct filecopy_options *opts)
{
	struct timeval atime, mtime, btime;
	struct timeval t1[2], t2[2];
	TIMESPEC_TO_TIMEVAL(t1 + 0, &opts->src.sbuf.st_atim); t2[0] = t1[0];
	TIMESPEC_TO_TIMEVAL(t1 + 1, &opts->src.sbuf.st_birthtim);
	TIMESPEC_TO_TIMEVAL(t2 + 1, &opts->src.sbuf.st_mtim);
#ifndef O_SYMLINK
	if (opts->dst.type == TYPE_LINK)
		(void)lutimes(opts->dst.name, t1);
	else
#endif
		(void)futimes(opts->dst.fd, t1);
#ifdef O_SYMLINK
	if (opts->dst.type == TYPE_LINK)
		(void)lutimes(opts->dst.name, t2);
	else
#endif
		(void)futimes(opts->dst.fd, t2);
	return 0;
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
	acl_t orig_acl = NULL;
	
	if (opts == NULL) {
		errno = EFAULT;
		return -1;
	}

	/*
	 * We do this here so we can bail out early if there
	 * is a memory allocation problem.  This makes the code
	 * more annoying, but it saves quite a bit.
	 */
	if (opts->data) {
		opts->buffer = malloc(kBufferSize);
		if (opts->buffer == NULL) {
			terror = ENOMEM;
			goto done;
		}
		opts->bufsize = kBufferSize;
	}
	
	if (open_source(opts, src) == -1) {
		terror = errno;
		goto done;
	}
	if (open_dest(opts, dst) == -1) {
		terror = errno;
		goto done;
	}
#if DEBUG_DEVEL
	acl_t tmp_acl;
	tmp_acl = get_acl(&opts->dst);
	if (tmp_acl) {
		warnx("%s(%d):  dst_acl = %s", __FUNCTION__, __LINE__, acl_to_text(tmp_acl, NULL));
		acl_free(tmp_acl);
	}
#endif
	/*
	 * Now we need to see if the copy is something we can do.
	 * If we're copying data, we can only copy directory -> directory,
	 * symlink -> symlink, and file -> file.  If we're copying
	 * metadata, we can do any combination.
	 */
	if (opts->data) {
		filecopy_status_t kr;	// Kopy Result
		if (opts->src.type != opts->dst.type) {
			terror = EINVAL;
			goto done;
		}
		/*
		 * We can only copy data for files.
		 * Symlinks were created in open_dest().
		 */
		if (opts->src.type == TYPE_FILE) {
			kr = copy_data(opts);
			if (kr == FC_ABORT) {
				terror = errno;
				goto done;
			}
		}
	}
	
#if DEBUG_DEVEL
	tmp_acl = get_acl(&opts->dst);
	if (tmp_acl) {
		warnx("%s(%d):  dst_acl = %s", __FUNCTION__, __LINE__, acl_to_text(tmp_acl, NULL));
		acl_free(tmp_acl);
	}
#endif
	/*
	 * Copy EAs, if requested
	 */
	if (opts->xattr) {
		filecopy_status_t kr = copy_xattrs(opts);
		if (kr == FC_ABORT) {
			terror = errno;
			warn("Could not copy xattrs");
			goto done;
		}
	}

#if DEBUG_DEVEL
	tmp_acl = get_acl(&opts->dst);
	if (tmp_acl) {
		warnx("%s(%d):  dst_acl = %s", __FUNCTION__, __LINE__, acl_to_text(tmp_acl, NULL));
		acl_free(tmp_acl);
	}
#endif
	if (opts->posix) {
		copy_posix(opts);
	}
	
#if DEBUG_DEVEL
	tmp_acl = get_acl(&opts->dst);
	if (tmp_acl) {
		warnx("%s(%d):  dst_acl = %s", __FUNCTION__, __LINE__, acl_to_text(tmp_acl, NULL));
		acl_free(tmp_acl);
	}
#endif
	
	if (opts->acl) {
		copy_acl(opts);
	}
	// Recursive copies will remove the uberace themselves later
	if (!opts->recursion)
		remove_uberace(&opts->dst);
	
#if DEBUG_DEVEL
	tmp_acl = get_acl(&opts->dst);
	if (tmp_acl) {
		warnx("%s(%d):  dst_acl = %s", __FUNCTION__, __LINE__, acl_to_text(tmp_acl, NULL));
		acl_free(tmp_acl);
	}
#endif
	if (opts->times) {
		(void)copy_times(opts);
	}

done:
	if (opts->buffer)
		free(opts->buffer);
	close_files(opts);
	if (terror) {	// Indicates an error
		if (opts->dst.flags & FLAG_CREATED)
			(void)remove(dst);
		errno = terror;
		retval = -1;
	}
	return retval;
}
