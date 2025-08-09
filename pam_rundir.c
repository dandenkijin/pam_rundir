/*
 * pam_rundir - Copyright (C) 2015 Olivier Brunel
 *
 * pam_rundir.c
 * Copyright (C) 2015 Olivier Brunel <jjk@jjacky.com>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see http://www.gnu.org/licenses/
 */

#include "config.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

/* PAM headers must be included before any forward declarations */
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_appl.h>

/* Constants */
#define MAX_UID_LENGTH 10          /* Maximum length of a 32-bit integer as string */
#define COUNTER_BUFFER_SIZE 20     /* Should be enough for any 64-bit counter */
#define MAX_PATH_LEN 4096          /* Maximum path length */
#define LOCK_RETRIES 5             /* Maximum retries for file locking */
#define LOCK_RETRY_DELAY 100000    /* Delay between lock retries in microseconds */

/* Forward declarations */
static void log_error(pam_handle_t *pamh, const char *format, ...);
static int ensure_parent_dir(pam_handle_t *pamh);
static int open_and_lock(const char *path, pam_handle_t *pamh);
static int read_counter(int fd);
static int write_counter(int fd, int count);
static void print_filename(char *buf, int uid, int l);
static int intlen(int n);

/* PAM cleanup function for session data */
static void cleanup_session_data(pam_handle_t *pamh, void *data, int error_status) {
    (void)pamh;        /* Unused parameter */
    (void)error_status; /* Unused parameter */
    free(data);
}

#define FLAG_NAME           "pam_rundir_has_counted"

/* Ensure the parent directory for runtime directories exists with proper permissions */
static int
ensure_parent_dir(pam_handle_t *pamh)
{
    struct stat st;
    mode_t old_umask = umask(S_IWOTH);
    int ret = 0;
    
    /* Try to create the directory if it doesn't exist */
    if (mkdir(PARENT_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
        if (errno != EEXIST) {
            log_error(pamh, "Failed to create directory %s: %m", PARENT_DIR);
            goto out;
        }
        
        /* Directory exists, verify it's actually a directory */
        if (stat(PARENT_DIR, &st) != 0) {
            log_error(pamh, "Failed to stat %s: %m", PARENT_DIR);
            goto out;
        }
        
        if (!S_ISDIR(st.st_mode)) {
            log_error(pamh, "%s exists but is not a directory", PARENT_DIR);
            goto out;
        }
    }
    
    /* Set proper ownership (root:root) */
    if (chown(PARENT_DIR, 0, 0) != 0) {
        log_error(pamh, "Failed to set ownership of %s: %m", PARENT_DIR);
        /* Non-fatal, continue */
    }
    
    /* Set secure permissions (rwxr-xr-x) */
    if (chmod(PARENT_DIR, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        log_error(pamh, "Failed to set permissions on %s: %m", PARENT_DIR);
        /* Non-fatal, continue */
    }
    
    ret = 1; /* Success */
    
out:
    umask(old_umask);
    return ret;
}

static int
intlen (int n)
{
    int l;

    for (l = 1; ; ++l)
    {
        if (n < 10)
            break;
        n /= 10;
    }

    return l;
}

static void
print_int (char *s, int n, int l)
{
    s += l;
    for (;;)
    {
        const char digits[] = "0123456789";

        *--s = digits[n % 10];
        if (n < 10)
            break;
        n /= 10;
    }
}

/* Log an error message to syslog */
static void
log_error(pam_handle_t *pamh, const char *format, ...)
{
    (void)pamh;  /* Unused parameter */
    va_list args;
    char buf[1024];
    
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    
    /* Log to syslog with the PAM module name */
    openlog("pam_rundir", LOG_PID | LOG_CONS, LOG_AUTHPRIV);
    syslog(LOG_ERR, "%s", buf);
    closelog();
    
    /* Also log to stderr if running in debug mode */
#ifdef DEBUG
    fprintf(stderr, "pam_rundir: %s\n", buf);
#endif
}

/* Safely open and lock a file with retries */
static int
open_and_lock (const char *file, pam_handle_t *pamh)
{
    int fd;
    int retries = 0;
    struct stat st;

    /* Ensure parent directory exists */
    char path[PATH_MAX];
    char *last_slash = strrchr(file, '/');
    if (last_slash) {
        size_t dir_len = last_slash - file;
        if (dir_len >= PATH_MAX) {
            if (pamh) log_error(pamh, "Path too long: %.*s", (int)dir_len, file);
            return -1;
        }
        strncpy(path, file, dir_len);
        path[dir_len] = '\0';
        
        if (stat(path, &st) == -1) {
            if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == -1 && errno != EEXIST) {
                if (pamh) log_error(pamh, "Failed to create directory %s: %m", path);
                return -1;
            }
        } else if (!S_ISDIR(st.st_mode)) {
            if (pamh) log_error(pamh, "%s exists but is not a directory", path);
            return -1;
        }
    }

    /* Try to open the file with retries */
    while (retries < LOCK_RETRIES) {
        fd = open(file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (fd >= 0) break;
        
        if (errno != EINTR && errno != EAGAIN) {
            if (pamh) log_error(pamh, "Failed to open %s: %m", file);
            return -1;
        }
        
        usleep(LOCK_RETRY_DELAY);
        retries++;
    }
    
    if (fd < 0) {
        if (pamh) log_error(pamh, "Failed to open %s after %d retries: %m", file, LOCK_RETRIES);
        return -1;
    }

    /* Try to get an exclusive lock with retries */
    retries = 0;
    while (retries < LOCK_RETRIES) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            return fd;  /* Success */
        }
        
        if (errno != EWOULDBLOCK && errno != EINTR) {
            close(fd);
            if (pamh) log_error(pamh, "Failed to lock %s: %m", file);
            return -1;
        }
        
        usleep(LOCK_RETRY_DELAY);
        retries++;
    }
    
    close(fd);
    if (pamh) log_error(pamh, "Failed to lock %s after %d retries: %m", file, LOCK_RETRIES);
    return -1;
}

static inline void
print_filename (char *s, int uid, int l)
{
    /* construct file name, e.g: "/run/users/.1000" */
    memcpy (s, PARENT_DIR, sizeof (PARENT_DIR) - 1);
    s[sizeof (PARENT_DIR) - 1] = '/';
    s[sizeof (PARENT_DIR)] = '.';
    print_int (s + sizeof (PARENT_DIR) + 1, uid, l);
    s[sizeof (PARENT_DIR) + 1 + l] = '\0';

}

static int
read_counter (int fd)
{
    int count = 0;

    /* read counter in file, as ascii string */
    for (;;)
    {
        char buf[4];
        int p;
        int r;

        r = read (fd, buf, sizeof (buf));
        if (r == 0)
            break;
        else if (r < 0)
        {
            if (errno == EINTR)
                continue;
            else
                return -1;
        }
        else if (count == 0 && r == 1 && buf[0] == '-')
            /* special case: dir not usable, but not a failure */
            return -2;

        for (p = 0; r > 0; --r, ++p)
        {
            if (buf[p] < '0' || buf[p] > '9')
                return -1;
            count *= 10;
            count += buf[p] - '0';
        }
    }
    return count;
}

/* basically, this is called when we tried to update the counter but failed,
 * leaving the file in an invalid state (i.e. only partial write, or no
 * truncate).
 * So here, we try to make the file "properly invalid" so any further attempt to
 * read it will lead to a no-op (because of invalid data). Obviously though, if
 * we fail to e.g. seek or write, we can't do anything else...
 * (Anyhow, this will likely never be called.)
 */
static void
emergency_invalidate_counter (int fd)
{
    int r;

    if (lseek (fd, 0, SEEK_SET) < 0)
        return;

    do { r = write (fd, "-", 1); }
    while (r < 0 && errno == EINTR);

    if (r == 1)
        do { r = ftruncate (fd, 1); }
        while (r < 0 && errno == EINTR);
}

static int
write_counter (int fd, int count)
{
    int r;
    int l;

    r = lseek (fd, 0, SEEK_SET);
    if (r < 0)
        return r;

    l = (count >= 0) ? intlen (count) : 1;
    {
        char buf[l];

        if (count >= 0)
            print_int (buf, count, l);
        else
            buf[0] = '-';

        for (;;)
        {
            int w = 0;

            r = write (fd, buf + w, l - w);
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                if (w > 0)
                    emergency_invalidate_counter (fd);
                return -1;
            }

            w += r;
            if (w == l)
                break;
        }

        do { r = ftruncate (fd, l); }
        while (r < 0 && errno == EINTR);
        if (r < 0)
            emergency_invalidate_counter (fd);
    }
    return r;
}

/* Safely remove a directory and its contents */
static int
rmrf (const char *path, pam_handle_t *pamh)
{
    int r = 0;
    DIR *dir;
    struct dirent *dp;
    size_t path_len;
    struct stat st;

    /* First try to unlink the path if it's a file */
    if (unlink(path) == 0) {
        return 0;
    } else if (errno != EISDIR) {
        if (pamh) log_error(pamh, "Failed to unlink %s: %m", path);
        return -1;
    }

    /* It's a directory, open it */
    dir = opendir(path);
    if (!dir) {
        if (pamh) log_error(pamh, "Failed to open directory %s: %m", path);
        return -1;
    }

    path_len = strlen(path);
    if (path_len >= MAX_PATH_LEN - 1) {
        if (pamh) log_error(pamh, "Path too long: %s", path);
        closedir(dir);
        return -1;
    }

    /* Process directory entries */
    while ((dp = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }

        /* Check if the new path would be too long */
        size_t name_len = strlen(dp->d_name);
        if (path_len + 1 + name_len >= MAX_PATH_LEN) {
            if (pamh) log_error(pamh, "Path too long: %s/%s", path, dp->d_name);
            r = -1;
            continue;
        }

        /* Build full path */
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, dp->d_name);
        
        /* Get file info */
        if (stat(full_path, &st) == -1) {
            if (pamh) log_error(pamh, "Failed to stat %s: %m", full_path);
            r = -1;
            continue;
        }

        /* Handle directory entries */
        if (S_ISDIR(st.st_mode)) {
            /* Recursively remove subdirectories */
            if (rmrf(full_path, pamh) != 0) {
                r = -1;
            }
        } else {
            /* Remove regular files */
            if (unlink(full_path) == -1) {
                if (pamh) log_error(pamh, "Failed to unlink %s: %m", full_path);
                r = -1;
            }
        }
    }
    closedir(dir);

    /* Remove the now-empty directory */
    if (rmdir(path) == -1) {
        if (pamh) log_error(pamh, "Failed to remove directory %s: %m", path);
        r = -1;
    }

    return r;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void) flags;
    (void) argc;
    (void) argv;
    int r;
    const char *user = NULL;
    struct passwd *pw = NULL;
    char file[MAX_PATH_LEN];
    int fd;
    int count = 0;
    uid_t uid;

    /* Get the flag we set in open_session */
    const void *data;
    r = pam_get_data(pamh, FLAG_NAME, &data);
    if (r != PAM_SUCCESS && r != PAM_NO_MODULE_DATA) {
        log_error(pamh, "Failed to get module data: %s", pam_strerror(pamh, r));
        return PAM_SESSION_ERR;
    }

    
    /* If no data was set, nothing to do */
    if (r == PAM_NO_MODULE_DATA || data == NULL) {
        return PAM_SUCCESS;
    }

    /* Security check: must be root */
    if (geteuid() != 0) {
        log_error(pamh, "Must be root to close session");
        return PAM_SESSION_ERR;
    }

    /* Get the username */
    r = pam_get_user(pamh, &user, NULL);
    if (r != PAM_SUCCESS || user == NULL || *user == '\0') {
        log_error(pamh, "Failed to get username: %s", 
                 r != PAM_SUCCESS ? pam_strerror(pamh, r) : "No username provided");
        return PAM_USER_UNKNOWN;
    }

    /* Get user info */
    pw = getpwnam(user);
    if (!pw) {
        log_error(pamh, "User %s not found in passwd database", user);
        return PAM_USER_UNKNOWN;
    }
    uid = pw->pw_uid;

    /* Get length for uid as ascii string */
    int l = intlen(uid);
    if (l <= 0 || l > MAX_UID_LENGTH) {
        log_error(pamh, "Invalid UID length for user %s", user);
        return PAM_SYSTEM_ERR;
    }

    /* Ensure the parent directory exists */
    if (!ensure_parent_dir(pamh)) {
        log_error(pamh, "Failed to ensure parent directory exists");
        return PAM_SESSION_ERR;
    }

    /* Construct the counter file path */
    print_filename(file, uid, l);

    /* Open and lock the counter file */
    fd = open_and_lock(file, pamh);
    if (fd < 0) {
        log_error(pamh, "Failed to open/lock counter file %s", file);
        return PAM_SESSION_ERR;
    }

    /* Read the current counter value */
    count = read_counter(fd);
    if (count < 0) {
        /* -2 means directory is not usable, but not a failure */
        r = (count == -2) ? 0 : -1;
        if (r < 0) {
            log_error(pamh, "Failed to read counter from %s", file);
        }
        goto done;
    }

    /* Decrement counter, ensuring it doesn't go below zero */
    if (count > 0) {
        --count;
    }

    /* If counter reaches zero, remove the runtime directory */
    if (count == 0) {
        /* Construct runtime dir name by removing the dot before UID */
        memmove(file + sizeof(PARENT_DIR) - 1, file + sizeof(PARENT_DIR), l + 1);
        
        if (rmrf(file, pamh) < 0) {
            log_error(pamh, "Failed to remove directory %s", file);
            count = -1; /* Mark as error */
        }
    }

    /* Update the counter */
    r = write_counter(fd, count);
    if (r < 0) {
        log_error(pamh, "Failed to update counter in %s", file);
        goto done;
    }

    if (count == -1) {
        r = -1;
        log_error(pamh, "Error state encountered during directory removal");
    }

done:
    /* Clean up */
    close(fd); /* Also releases the lock */
    
    /* Clear the module data */
    pam_set_data(pamh, FLAG_NAME, NULL, NULL);

    return (r == 0) ? PAM_SUCCESS : PAM_SESSION_ERR;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void) flags;
    (void) argc;
    (void) argv;
    int r = PAM_SUCCESS;
    const char *user = NULL;
    struct passwd *pw = NULL;
    char file[MAX_PATH_LEN];
    char env_var[MAX_PATH_LEN + sizeof(VAR_NAME)];
    int fd = -1;
    int count = 0;
    uid_t uid;
    gid_t gid;
    int l;

    /* Security check: must be root */
    if (geteuid() != 0) {
        log_error(pamh, "Must be root to open session");
        return PAM_SESSION_ERR;
    }

    /* Get the username */
    r = pam_get_user(pamh, &user, NULL);
    if (r != PAM_SUCCESS || user == NULL || *user == '\0') {
        log_error(pamh, "Failed to get username: %s", 
                 r != PAM_SUCCESS ? pam_strerror(pamh, r) : "No username provided");
        return PAM_USER_UNKNOWN;
    }

    /* Get user info */
    pw = getpwnam(user);
    if (!pw) {
        log_error(pamh, "User %s not found in passwd database", user);
        return PAM_USER_UNKNOWN;
    }
    uid = pw->pw_uid;
    gid = pw->pw_gid;

    /* Get length for uid as ascii string */
    l = intlen(uid);
    if (l <= 0 || l > MAX_UID_LENGTH) {
        log_error(pamh, "Invalid UID length for user %s", user);
        return PAM_SYSTEM_ERR;
    }

    /* Ensure the parent directory exists */
    if (!ensure_parent_dir(pamh)) {
        log_error(pamh, "Failed to ensure parent directory exists");
        return PAM_SESSION_ERR;
    }

    /* Construct the counter file path */
    print_filename(file, uid, l);

    /* Open and lock the counter file */
    fd = open_and_lock(file, pamh);
    if (fd < 0) {
        log_error(pamh, "Failed to open/lock counter file %s", file);
        return PAM_SESSION_ERR;
    }

    /* Read the current counter value */
    count = read_counter(fd);
    if (count < 0) {
        /* -2 means directory is not usable, but not a failure */
        if (count != -2) {
            log_error(pamh, "Failed to read counter from %s", file);
            r = PAM_SESSION_ERR;
            goto done;
        }
        count = 0; /* Start fresh if directory was not usable */
    }

    /* Construct runtime dir name by removing the dot before UID */
    char runtime_dir[MAX_PATH_LEN];
    strncpy(runtime_dir, file, sizeof(runtime_dir) - 1);
    runtime_dir[sizeof(runtime_dir) - 1] = '\0';
    memmove(runtime_dir + sizeof(PARENT_DIR) - 1, 
            runtime_dir + sizeof(PARENT_DIR), 
            l + 1);

    /* Increment the counter first to maintain consistency */
    r = write_counter(fd, count + 1);
    if (r < 0) {
        log_error(pamh, "Failed to update counter in %s", file);
        goto done;
    }

    /* Flag for processing on close_session */
    int *session_data = malloc(sizeof(int));
    if (!session_data) {
        log_error(pamh, "Memory allocation failed");
        r = PAM_BUF_ERR;
        goto revert_counter;
    }
    *session_data = 1;

    /* Set the module data to indicate we've incremented the counter */
    r = pam_set_data(pamh, FLAG_NAME, session_data, cleanup_session_data);
    if (r != PAM_SUCCESS) {
        log_error(pamh, "Failed to set module data: %s", pam_strerror(pamh, r));
        free(session_data);
        goto revert_counter;
    }

    /* Set effective UID/GID to the user's for directory creation */
    if (setegid(gid) < 0 || seteuid(uid) < 0) {
        log_error(pamh, "Failed to set effective UID/GID for user %s", user);
        r = PAM_SESSION_ERR;
        goto revert_counter;
    }

    /* Create the runtime directory if it doesn't exist */
    if (mkdir(runtime_dir, S_IRWXU) != 0 && errno != EEXIST) {
        log_error(pamh, "Failed to create directory %s: %m", runtime_dir);
        r = PAM_SESSION_ERR;
        goto restore_privs;
    }

    /* Set the runtime directory in the environment */
    snprintf(env_var, sizeof(env_var), "%s=%s", VAR_NAME, runtime_dir);
    r = pam_putenv(pamh, env_var);
    if (r != PAM_SUCCESS) {
        log_error(pamh, "Failed to set %s environment variable", VAR_NAME);
        r = PAM_SESSION_ERR;
        goto restore_privs;
    }

    /* Set proper ownership of the directory */
    if (chown(runtime_dir, uid, gid) < 0) {
        log_error(pamh, "Failed to set ownership of %s: %m", runtime_dir);
        /* Non-fatal error, continue */
    }

    /* Set proper permissions (user rwx only) */
    if (chmod(runtime_dir, S_IRWXU) < 0) {
        log_error(pamh, "Failed to set permissions on %s: %m", runtime_dir);
        /* Non-fatal error, continue */
    }

    /* Success path */
    r = PAM_SUCCESS;
    goto done;

restore_privs:
    /* Restore root privileges */
    if (seteuid(0) < 0 || setegid(0) < 0) {
        log_error(pamh, "FATAL: Failed to restore root privileges");
        /* Continue anyway */
    }

revert_counter:
    /* If we incremented the counter but failed afterward, decrement it */
    if (count >= 0) {
        if (write_counter(fd, count) < 0) {
            log_error(pamh, "Failed to revert counter in %s", file);
            /* Continue anyway */
        }
    }
    r = PAM_SESSION_ERR;

    /* If we set the module data but failed afterward, clear it */
    if (r != PAM_SUCCESS) {
        pam_set_data(pamh, FLAG_NAME, NULL, NULL);
    }

done:
    /* Close the file descriptor (also releases the lock) */
    if (fd >= 0) {
        close(fd);
    }

    return r;
}

#ifdef PAM_STATIC
struct pam_module _pam_rundir_modstruct = {
     "pam_rundir",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL
};
#endif
