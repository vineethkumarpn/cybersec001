#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define INCOMING_DIRECTORY "/var/lib/vm-artifacts/incoming"
#define MAX_ARTIFACT_SIZE (64U * 1024U * 1024U)
#define SHA256_SIZE 32

static int is_safe_basename(const char *name)
{
    if (name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;

    for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; p++) {
        if (!( (*p >= 'a' && *p <= 'z') ||
               (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') ||
               *p == '.' || *p == '_' || *p == '-'))
            return 0;
    }

    return 1;
}

static int parse_sha256(const char *hex, unsigned char digest[SHA256_SIZE])
{
    if (strlen(hex) != SHA256_SIZE * 2)
        return 0;

    for (size_t i = 0; i < SHA256_SIZE; i++) {
        unsigned char high = (unsigned char)hex[i * 2];
        unsigned char low = (unsigned char)hex[i * 2 + 1];
        int high_value;
        int low_value;

        if (high >= '0' && high <= '9')
            high_value = high - '0';
        else if (high >= 'a' && high <= 'f')
            high_value = high - 'a' + 10;
        else if (high >= 'A' && high <= 'F')
            high_value = high - 'A' + 10;
        else
            return 0;

        if (low >= '0' && low <= '9')
            low_value = low - '0';
        else if (low >= 'a' && low <= 'f')
            low_value = low - 'a' + 10;
        else if (low >= 'A' && low <= 'F')
            low_value = low - 'A' + 10;
        else
            return 0;

        digest[i] = (unsigned char)((high_value << 4) | low_value);
    }

    return 1;
}

static void print_sha256(const unsigned char digest[SHA256_SIZE])
{
    for (size_t i = 0; i < SHA256_SIZE; i++)
        printf("%02x", digest[i]);
}

int main(int argc, char **argv)
{
    unsigned char expected[SHA256_SIZE];
    unsigned char actual[EVP_MAX_MD_SIZE];
    unsigned int actual_length = 0;
    unsigned char buffer[16384];
    uint64_t total = 0;
    int directory_fd = -1;
    int artifact_fd = -1;
    EVP_MD_CTX *context = NULL;
    int result = EXIT_FAILURE;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <artifact-basename> <trusted-sha256>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (!is_safe_basename(argv[1])) {
        fprintf(stderr, "Artifact name must be a simple basename (no path components).\n");
        return EXIT_FAILURE;
    }

    if (!parse_sha256(argv[2], expected)) {
        fprintf(stderr, "Expected SHA-256 must be exactly 64 hexadecimal characters.\n");
        return EXIT_FAILURE;
    }

    directory_fd = open(INCOMING_DIRECTORY, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd == -1) {
        fprintf(stderr, "Cannot open incoming directory %s: %s\n",
                INCOMING_DIRECTORY, strerror(errno));
        goto cleanup;
    }

    artifact_fd = openat(directory_fd, argv[1],
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (artifact_fd == -1) {
        fprintf(stderr, "Cannot open staged artifact: %s\n", strerror(errno));
        goto cleanup;
    }

    struct stat metadata;
    if (fstat(artifact_fd, &metadata) == -1) {
        fprintf(stderr, "Cannot inspect staged artifact: %s\n", strerror(errno));
        goto cleanup;
    }

    if (!S_ISREG(metadata.st_mode)) {
        fprintf(stderr, "Staged artifact must be a regular file.\n");
        goto cleanup;
    }

    if (metadata.st_size < 0 || (uint64_t)metadata.st_size > MAX_ARTIFACT_SIZE) {
        fprintf(stderr, "Staged artifact exceeds the 64 MiB size limit.\n");
        goto cleanup;
    }

    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Could not initialize SHA-256.\n");
        goto cleanup;
    }

    for (;;) {
        ssize_t bytes_read = read(artifact_fd, buffer, sizeof(buffer));
        if (bytes_read == 0)
            break;
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Could not read staged artifact: %s\n", strerror(errno));
            goto cleanup;
        }

        total += (uint64_t)bytes_read;
        if (total > MAX_ARTIFACT_SIZE) {
            fprintf(stderr, "Staged artifact exceeds the 64 MiB size limit.\n");
            goto cleanup;
        }

        if (EVP_DigestUpdate(context, buffer, (size_t)bytes_read) != 1) {
            fprintf(stderr, "Could not calculate SHA-256.\n");
            goto cleanup;
        }
    }

    if (EVP_DigestFinal_ex(context, actual, &actual_length) != 1 ||
        actual_length != SHA256_SIZE) {
        fprintf(stderr, "Could not finalize SHA-256.\n");
        goto cleanup;
    }

    printf("SHA-256: ");
    print_sha256(actual);
    putchar('\n');

    if (memcmp(actual, expected, SHA256_SIZE) != 0) {
        fprintf(stderr, "Hash mismatch; artifact is NOT verified.\n");
        goto cleanup;
    }

    printf("Hash matches the supplied trusted digest. No file was copied or executed.\n");
    result = EXIT_SUCCESS;

cleanup:
    EVP_MD_CTX_free(context);
    if (artifact_fd != -1)
        close(artifact_fd);
    if (directory_fd != -1)
        close(directory_fd);
    return result;
}