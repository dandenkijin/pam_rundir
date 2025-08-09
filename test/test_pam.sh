#!/bin/bash

# Test PAM module directly
TEST_USER="pamtestuser"
TEST_PASS="testpass123"
PAM_SERVICE="sshd"

# Create a test PAM config
echo "Creating test PAM configuration..."
sudo tee /tmp/pam_test.conf > /dev/null <<EOL
# Test PAM configuration for pam_rundir
auth required pam_permit.so
account required pam_permit.so
password required pam_permit.so
session required pam_permit.so
session optional pam_rundir.so debug
EOL

# Create a simple PAM test script
cat > /tmp/pam_test.c <<'EOL'
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <string.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <username>\n", argv[0]);
        return 1;
    }

    const char *username = argv[1];
    pam_handle_t *pamh = NULL;
    int retval;
    
    // Initialize PAM
    retval = pam_start("pam_test", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, retval));
        return 1;
    }
    
    printf("PAM started successfully\n");
    
    // Set PAM_RUSER to the username
    retval = pam_set_item(pamh, PAM_RUSER, username);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_set_item(PAM_RUSER) failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return 1;
    }
    
    // Set PAM_TTY
    retval = pam_set_item(pamh, PAM_TTY, "test_console");
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_set_item(PAM_TTY) failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return 1;
    }
    
    printf("PAM items set successfully\n");
    
    // Open session
    printf("Opening PAM session...\n");
    retval = pam_open_session(pamh, 0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_open_session failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return 1;
    }
    
    printf("PAM session opened successfully\n");
    
    // Get environment variables
    printf("\nEnvironment variables from PAM:\n");
    char **env = pam_getenvlist(pamh);
    if (env) {
        for (char **var = env; *var != NULL; var++) {
            printf("  %s\n", *var);
            free(*var);
        }
        free(env);
    }
    
    // Close session
    printf("\nClosing PAM session...\n");
    retval = pam_close_session(pamh, 0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_close_session failed: %s\n", pam_strerror(pamh, retval));
    } else {
        printf("PAM session closed successfully\n");
    }
    
    // End PAM transaction
    pam_end(pamh, retval);
    return retval == PAM_SUCCESS ? 0 : 1;
}
EOL

# Compile the test program
echo "Compiling test program..."
gcc -o /tmp/pam_test /tmp/pam_test.c -lpam -lpam_misc

# Run the test
echo "Running PAM test..."
sudo PAM_PATH=/tmp/pam_test.conf /tmp/pam_test "$TEST_USER"

# Clean up
rm -f /tmp/pam_test.c /tmp/pam_test /tmp/pam_test.conf
