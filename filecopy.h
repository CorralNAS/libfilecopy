#ifndef _FILECOPY_H
# define _FILECOPY_H

# ifdef __cplusplus
//extern "C" {
# endif
	
// values returned by callbacks.
typedef enum {
	FC_ABORT = 0,	// Stop with prejudice, returning an error to the caller
	FC_CONTINUE,	// Continue with operation
	FC_SKIP,	// Skip this file or EA
} filecopy_status_t;

// Opaque type, holds all the options.
typedef void *filecopy_options_t;

/*
 * Status and error handlers use the same type of function callback.  It
 * uses variable arguments, so they need to either use <stdarg.h>, or only
 * look at the cause and the context.
 */
typedef filecopy_status_t (*filecopy_callback_t)(const char *what, void *context, ...);
#ifdef __BLOCKS__
typedef filecopy_status_t (^filecopy_block_t)(const char *, ...);
#endif

extern filecopy_options_t filecopy_options_init(void);
extern void filecopy_options_release(filecopy_options_t);

/*
 * filecopy_set_option() can not do the error checking that the specific
 * ones can, but you can set a bunch of options at once.
 * All of the set functions return -1 on error, and set errno.
 * The get functions will return the value, which may be 0 or NULL if it hasn't
 * been set.  (If the option has a default, that's what will be returned, if it
 * hasn't been set yet.)
 */
extern int filecopy_set_option(filecopy_options_t, const char *opt, ...);

extern int filecopy_set_bool(filecopy_options_t, const char *opt, int v);
extern int filecopy_get_bool(filecopy_options_t, const char *opt);

extern int filecopy_set_int(filecopy_options_t, const char *opt, int v);
extern int filecopy_get_int(filecopy_options_t, const char *opt);

extern int filecopy_set_string(filecopy_options_t, const char *opt, const char *v);
extern char *filecopy_get_string(filecopy_options_t, const char *opt);

extern int filecopy_set_callback(filecopy_options_t, const char *opt, filecopy_callback_t cb);
extern filecopy_callback_t *filecopy_get_callback(filecopy_options_t, const char *opt);

# ifdef __BLOCKS__
extern int *filecopy_set_block(filecopy_options_t, const char *opt, filecopy_block_t);
extern filecopy_block_t filecopy_get_block(filecopy_options_t, const char *opt);
#endif

// And the options are:
extern const char *fc_option_data;	// Boolean [aka int].  Whether or not to copy data.
extern const char *fc_option_xattr;	// Boolean [aka int].  Whether or not to copy EAs.
extern const char *fc_option_acl;	// Boolean [aka int].  Whether or not to copy ACLs.
extern const char *fc_option_perms;	// Boolean [aka int].  Whether or not to copy file mode/owner/group
extern const char *fc_option_times;	// Boolean [aka int].  Whether or not to copy files (as much as possible)
extern const char *fc_option_recursion;	// Boolean [aka int].  Whether or not to recursively copy.
extern const char *fc_option_follow;	// Boolean [aka int].  Whether or not to copy symlinks, or what they point to.

extern const char *fc_option_context;	// void*.  Sets the context for callbacks.

/*
 * Option to set a status callback.  This includes preparation, start,
 * progress, and completion.  All status callbacks use this.
 */
extern const char *fc_option_status_cb;

/*
 * Option to set an error callback.  This can happen during preparation or
 * in the middle of an operation.  All error callbacks use this.
 */
extern const char *fc_option_error_cb;

#ifdef __BLOCKS__
/*
 * Option to set a status block.  Other than the context parameter,
 * this is identical to the status callback.  (That is, where a
 * callback would be (*cb)(name, context, ...), the block is
 * (*b)(name, ...).)
 */
extern const char *fc_option_status_block;

/*
 * Option to set an error block.  Other than the context parameter,
 * this is identical to the error callback.
 */
extern const char *fc_option_error_block;
#endif

/*
 * The following are used by the callbacks.
 * fc_status_<foo> is used by the status callback;
 * fc_error_<foo> is used by the error callback.
 */

/*
 * Indicates a data copy is about to start.
 * (*cb)(fc_status_data_start, context)
 * Return FC_ABORT to exit out (errno will be set to 0, but
 * the function will return -1), FC_SKIP to skip copying the
 * data, and FC_CONTINUE to keep going.
 */
extern const char *fc_status_data_start;

/*
 * Data copy progress.
 * (*cb)(fc_status_data_progress, context, off_t expected, off_t copied)
 * "expected" is the amount of data it expects to copy, in bytes; note
 * that there is no locking going on, so it may end up being different.
 * Return FC_ABORT to exit out, FC_SKIP to skip copying the data,
 * and FC_CONTINUE to keep going.
 */
extern const char *fc_status_data_progress;

/*
 * Data copy has finished.
 * (*cb)(fc_status_data_completion, context, off_t copied)
 * FC_ABORT will cause the function to exit out (errno set to 0,
 * but returning -1); FC_SKIP and FC_CONTINUE both simply continue.
 */
extern const char *fc_status_data_completion;

/*
 * Indicates an error has occurred while preparing the copy.
 * This typically means while opening the source or destination.
 * It cannot continue form this case; FC_CONTINUE will simply cause
 * the function to return 0.
 * Called as (*cb)(fc_error_preparation, context, char *which, int errno)
 * where "which" is either the src or dst file.
 */
extern const char *fc_error_preparation;

/*
 * Called when an error has occurred while copying data.
 * (*cb)(fc_error_data, context, off_t copied, int errno)
 * FC_ABORT causes the function to exit (with errno set to the
 * same value as the callback was given); FC_SKIP causes the
 * function to exit with no error, while FC_CONTINUE causes it
 * to continue trying to copy the rest of the stages.
 */
extern const char *fc_error_data;


/*
 * Called when copying extended attributes, before anything
 * else.
 * (*cb)(fc_status_extattr_start, void *context, char *srcname)
 * FC_ABORT causes the function to exit (with errno set ot 0,
 * but returning -1); FC_SKIP causes it to skip the extattr stage
 * while FC_CONTINUE lets it continue.
 */
extern const char *fc_status_extattr_start;

/*
 * Called when an error occurs during an EA copy.
 * (*cb)(fc_error_extattr, void *context, char *srcname, char *ns, char *eaname, int errno)
 * FC_ABORT causes the function to exit (with errno set to the vaue passed in);
 * FC_SKIP causes ihe function to stop copying EAs;
 * FC_CONTINUE continues to the next EA (if any).
 */
extern const char *fc_error_extattr;

/*
 * Called when copying an extended attribute, before
 * each EA.
 * (*cb)(fc_status_extattr, context, char *srcname, char *namespace, char *eaname)
 * Returning FC_ABORT causes the function to exit (with errno set
 * to 0, but returning -1), FC_SKIP will ignore this EA, and FC_CONTNUE
 * will attempt to do the copy.
 */
extern const char *fc_status_extattr;

/*
 * Called when finished with an EA.  Note that this is called with
 * two formats:
 * (*cb)(fc_status_extattr_completion, context, char *srcname, char *namespace, char *eaname, off_t nbytes)
 * OR
 * (*cb)(fc_status_extattr_completion, context, char *srcname, NULL);
 *
 * The first use indicates an individual EA has finished, and how much was copied;
 * the second use indicates the EA copying stage has completed.
 * Returning FC_ABORT causes the function to exit (with errno set to
 * 0, but returning -1); FC_SKIP and FC_CONTINUE behave the same way,
 * progressing to either the next EA or the next stage.
 */
extern const char *fc_status_extattr_completion;

// And now the big enchilada
extern int filecopy(filecopy_options_t, const char *src, const char *dst);

# ifdef __cplusplus
//}
# endif /* __cplusplus */

#endif /* _FILECOPY_H */
