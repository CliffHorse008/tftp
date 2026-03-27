#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TFTP_PORT 69
#define TFTP_DEFAULT_DATA_SIZE 512
#define TFTP_CONTROL_PACKET_SIZE 516
#define TFTP_REQUEST_PACKET_SIZE 2048
#define TFTP_OACK_PACKET_SIZE 512
#define TFTP_MIN_BLKSIZE 8
#define TFTP_MAX_BLKSIZE 65464
#define TFTP_RETRIES 5
#define TFTP_DEFAULT_TIMEOUT_SEC 3
#define NETASCII_BUFFER_SIZE 4096

enum tftp_opcode {
    TFTP_RRQ = 1,
    TFTP_WRQ = 2,
    TFTP_DATA = 3,
    TFTP_ACK = 4,
    TFTP_ERROR = 5,
    TFTP_OACK = 6,
};

enum tftp_error_code {
    TFTP_ERR_UNDEFINED = 0,
    TFTP_ERR_NOT_FOUND = 1,
    TFTP_ERR_ACCESS = 2,
    TFTP_ERR_DISK_FULL = 3,
    TFTP_ERR_ILLEGAL_OP = 4,
    TFTP_ERR_UNKNOWN_TID = 5,
    TFTP_ERR_EXISTS = 6,
    TFTP_ERR_NO_SUCH_USER = 7,
};

struct request_info {
    uint16_t opcode;
    char filename[256];
    char mode[32];
    bool has_tsize;
    uint64_t tsize;
    bool has_blksize;
    uint16_t blksize;
    bool has_timeout;
    uint8_t timeout;
};

static volatile sig_atomic_t g_running = 1;

struct netascii_encode_state {
    uint8_t input[NETASCII_BUFFER_SIZE];
    size_t input_len;
    size_t input_pos;
    int pending_byte;
    bool eof;
};

struct netascii_decode_state {
    bool pending_cr;
};

static int parse_port(const char *text, uint16_t *port) {
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (text[0] == '\0' || end == NULL || *end != '\0') {
        return -1;
    }
    if (value < 1 || value > 65535) {
        return -1;
    }

    *port = (uint16_t)value;
    return 0;
}

static void handle_signal(int signo) {
    (void)signo;
    g_running = 0;
}

static void reap_children(int signo) {
    (void)signo;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static size_t bounded_strlen(const char *s, size_t max_len) {
    size_t i = 0;
    while (i < max_len && s[i] != '\0') {
        i++;
    }
    return i;
}

static uint16_t read_u16(const uint8_t *buf) {
    uint16_t value;
    memcpy(&value, buf, sizeof(value));
    return ntohs(value);
}

static void write_u16(uint8_t *buf, uint16_t value) {
    uint16_t net = htons(value);
    memcpy(buf, &net, sizeof(net));
}

static void log_client(const struct sockaddr_in *addr, const char *message) {
    char ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip)) == NULL) {
        snprintf(ip, sizeof(ip), "unknown");
    }

    fprintf(stderr, "[%s:%u] %s\n", ip, ntohs(addr->sin_port), message);
}

static bool request_uses_netascii(const struct request_info *req) {
    return strcasecmp(req->mode, "netascii") == 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t chunk = write(fd, buf + written, len - written);
        if (chunk < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        written += (size_t)chunk;
    }

    return 0;
}

static void init_netascii_encode_state(struct netascii_encode_state *state) {
    memset(state, 0, sizeof(*state));
    state->pending_byte = -1;
}

static ssize_t read_netascii_block(
    int fd,
    struct netascii_encode_state *state,
    uint8_t *out,
    size_t out_cap
) {
    size_t out_len = 0;

    while (out_len < out_cap) {
        if (state->pending_byte >= 0) {
            out[out_len++] = (uint8_t)state->pending_byte;
            state->pending_byte = -1;
            continue;
        }

        if (state->input_pos == state->input_len) {
            if (state->eof) {
                break;
            }

            ssize_t bytes_read = read(fd, state->input, sizeof(state->input));
            if (bytes_read < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (bytes_read == 0) {
                state->eof = true;
                break;
            }

            state->input_len = (size_t)bytes_read;
            state->input_pos = 0;
        }

        uint8_t ch = state->input[state->input_pos++];
        if (ch == '\n') {
            out[out_len++] = '\r';
            if (out_len < out_cap) {
                out[out_len++] = '\n';
            } else {
                state->pending_byte = '\n';
            }
            continue;
        }

        if (ch == '\r') {
            out[out_len++] = '\r';
            if (out_len < out_cap) {
                out[out_len++] = '\0';
            } else {
                state->pending_byte = '\0';
            }
            continue;
        }

        out[out_len++] = ch;
    }

    return (ssize_t)out_len;
}

static ssize_t decode_netascii_chunk(
    struct netascii_decode_state *state,
    const uint8_t *input,
    size_t input_len,
    bool final_chunk,
    uint8_t *output,
    size_t output_cap
) {
    size_t out_len = 0;

    for (size_t i = 0; i < input_len; i++) {
        uint8_t ch = input[i];

        if (!state->pending_cr) {
            if (ch == '\r') {
                state->pending_cr = true;
                continue;
            }

            if (out_len >= output_cap) {
                errno = EOVERFLOW;
                return -1;
            }
            output[out_len++] = ch;
            continue;
        }

        if (out_len >= output_cap) {
            errno = EOVERFLOW;
            return -1;
        }

        if (ch == '\n') {
            output[out_len++] = '\n';
            state->pending_cr = false;
            continue;
        }

        if (ch == '\0') {
            output[out_len++] = '\r';
            state->pending_cr = false;
            continue;
        }

        output[out_len++] = '\r';
        state->pending_cr = false;

        if (ch == '\r') {
            state->pending_cr = true;
            continue;
        }

        if (out_len >= output_cap) {
            errno = EOVERFLOW;
            return -1;
        }
        output[out_len++] = ch;
    }

    if (final_chunk && state->pending_cr) {
        if (out_len >= output_cap) {
            errno = EOVERFLOW;
            return -1;
        }
        output[out_len++] = '\r';
        state->pending_cr = false;
    }

    return (ssize_t)out_len;
}

struct transfer_meter {
    const char *direction;
    const char *filename;
    bool has_total_bytes;
    uint64_t total_bytes;
    uint64_t transferred_bytes;
    uint64_t next_report_bytes;
    unsigned next_report_percent;
};

static void init_transfer_meter(
    struct transfer_meter *meter,
    const char *direction,
    const char *filename,
    bool has_total_bytes,
    uint64_t total_bytes
) {
    meter->direction = direction;
    meter->filename = filename;
    meter->has_total_bytes = has_total_bytes;
    meter->total_bytes = total_bytes;
    meter->transferred_bytes = 0;
    meter->next_report_bytes = 64 * 1024;
    meter->next_report_percent = 10;
}

static void log_transfer_progress(const struct sockaddr_in *addr, struct transfer_meter *meter, size_t delta_bytes, bool done) {
    char message[384];

    meter->transferred_bytes += delta_bytes;

    bool should_log = done;
    unsigned long long percent = 0;
    if (meter->has_total_bytes && meter->total_bytes > 0) {
        percent = (unsigned long long)(((uint64_t)meter->transferred_bytes * 100) / (uint64_t)meter->total_bytes);
        if (percent > 100) {
            percent = 100;
        }

        if (!should_log && percent >= meter->next_report_percent) {
            should_log = true;
            while (meter->next_report_percent <= percent && meter->next_report_percent < 100) {
                meter->next_report_percent += 10;
            }
        }
    } else if (!should_log && meter->transferred_bytes >= meter->next_report_bytes) {
        should_log = true;
        while (meter->next_report_bytes <= meter->transferred_bytes) {
            meter->next_report_bytes += 64 * 1024;
        }
    }

    if (!should_log) {
        return;
    }

    if (meter->has_total_bytes) {
        snprintf(
            message,
            sizeof(message),
            "%s progress for %s: %llu/%llu bytes (%llu%%)%s",
            meter->direction,
            meter->filename,
            (unsigned long long)meter->transferred_bytes,
            (unsigned long long)meter->total_bytes,
            percent,
            done ? ", completed" : ""
        );
    } else {
        snprintf(
            message,
            sizeof(message),
            "%s progress for %s: %llu bytes%s",
            meter->direction,
            meter->filename,
            (unsigned long long)meter->transferred_bytes,
            done ? ", completed" : ""
        );
    }

    log_client(addr, message);
}

static bool is_safe_filename(const char *filename) {
    if (filename[0] == '\0') {
        return false;
    }

    if (filename[0] == '/' || strstr(filename, "..") != NULL) {
        return false;
    }

    for (const char *p = filename; *p != '\0'; ++p) {
        if (*p == '\\') {
            return false;
        }
    }

    return true;
}

static int build_path(char *dst, size_t dst_size, const char *root_dir, const char *filename) {
    int written = snprintf(dst, dst_size, "%s/%s", root_dir, filename);
    if (written < 0 || (size_t)written >= dst_size) {
        return -1;
    }

    return 0;
}

static int open_upload_temp_file(const char *path, char *temp_path, size_t temp_path_size) {
    for (int attempt = 0; attempt < 16; ++attempt) {
        int written = snprintf(temp_path, temp_path_size, "%s.tmp.%ld.%d", path, (long)getpid(), attempt);
        if (written < 0 || (size_t)written >= temp_path_size) {
            errno = ENAMETOOLONG;
            return -1;
        }

        int fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) {
            return fd;
        }

        if (errno != EEXIST) {
            return -1;
        }
    }

    errno = EEXIST;
    return -1;
}

static ssize_t send_error_packet(
    int sockfd,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    uint16_t error_code,
    const char *message
) {
    uint8_t packet[TFTP_CONTROL_PACKET_SIZE];
    size_t msg_len = bounded_strlen(message, TFTP_CONTROL_PACKET_SIZE - 5);

    write_u16(packet, TFTP_ERROR);
    write_u16(packet + 2, error_code);
    memcpy(packet + 4, message, msg_len);
    packet[4 + msg_len] = '\0';

    return sendto(sockfd, packet, 5 + msg_len, 0, (const struct sockaddr *)client_addr, client_len);
}

static int set_socket_timeout(int sockfd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }

    return 0;
}

static int parse_u64(const char *text, uint64_t *value) {
    char *end = NULL;
    unsigned long long parsed;

    if (text[0] == '\0') {
        return -1;
    }

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0') {
        return -1;
    }

    *value = (uint64_t)parsed;
    return 0;
}

static int append_oack_option(
    uint8_t *packet,
    size_t packet_size,
    size_t *offset,
    const char *option,
    const char *value
) {
    size_t option_len = strlen(option) + 1;
    size_t value_len = strlen(value) + 1;

    if (*offset + option_len + value_len > packet_size) {
        errno = EMSGSIZE;
        return -1;
    }

    memcpy(packet + *offset, option, option_len);
    *offset += option_len;
    memcpy(packet + *offset, value, value_len);
    *offset += value_len;
    return 0;
}

static ssize_t send_oack_packet(
    int sockfd,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const uint8_t *packet,
    size_t packet_len
) {
    return sendto(sockfd, packet, packet_len, 0, (const struct sockaddr *)client_addr, client_len);
}

static int maybe_accept_options_for_rrq(
    const struct request_info *req,
    bool has_total_bytes,
    uint64_t total_bytes,
    uint8_t *packet,
    size_t packet_size,
    size_t *packet_len,
    size_t *block_size,
    int *timeout_sec
) {
    char value[32];
    size_t offset = 2;
    bool has_options = false;

    *block_size = TFTP_DEFAULT_DATA_SIZE;
    *timeout_sec = TFTP_DEFAULT_TIMEOUT_SEC;
    write_u16(packet, TFTP_OACK);

    if (req->has_tsize && has_total_bytes) {
        snprintf(value, sizeof(value), "%llu", (unsigned long long)total_bytes);
        if (append_oack_option(packet, packet_size, &offset, "tsize", value) < 0) {
            return -1;
        }
        has_options = true;
    }

    if (req->has_blksize) {
        snprintf(value, sizeof(value), "%u", req->blksize);
        if (append_oack_option(packet, packet_size, &offset, "blksize", value) < 0) {
            return -1;
        }
        *block_size = req->blksize;
        has_options = true;
    }

    if (req->has_timeout) {
        snprintf(value, sizeof(value), "%u", req->timeout);
        if (append_oack_option(packet, packet_size, &offset, "timeout", value) < 0) {
            return -1;
        }
        *timeout_sec = req->timeout;
        has_options = true;
    }

    *packet_len = has_options ? offset : 0;
    return 0;
}

static int maybe_accept_options_for_wrq(
    const struct request_info *req,
    uint8_t *packet,
    size_t packet_size,
    size_t *packet_len,
    size_t *block_size,
    int *timeout_sec,
    bool *has_total_bytes,
    uint64_t *total_bytes
) {
    char value[32];
    size_t offset = 2;
    bool has_options = false;

    *block_size = TFTP_DEFAULT_DATA_SIZE;
    *timeout_sec = TFTP_DEFAULT_TIMEOUT_SEC;
    *has_total_bytes = false;
    *total_bytes = 0;
    write_u16(packet, TFTP_OACK);

    if (req->has_tsize) {
        snprintf(value, sizeof(value), "%llu", (unsigned long long)req->tsize);
        if (append_oack_option(packet, packet_size, &offset, "tsize", value) < 0) {
            return -1;
        }
        *has_total_bytes = true;
        *total_bytes = req->tsize;
        has_options = true;
    }

    if (req->has_blksize) {
        snprintf(value, sizeof(value), "%u", req->blksize);
        if (append_oack_option(packet, packet_size, &offset, "blksize", value) < 0) {
            return -1;
        }
        *block_size = req->blksize;
        has_options = true;
    }

    if (req->has_timeout) {
        snprintf(value, sizeof(value), "%u", req->timeout);
        if (append_oack_option(packet, packet_size, &offset, "timeout", value) < 0) {
            return -1;
        }
        *timeout_sec = req->timeout;
        has_options = true;
    }

    *packet_len = has_options ? offset : 0;
    return 0;
}

static int recv_expected_packet(
    int sockfd,
    uint8_t *buf,
    size_t buf_size,
    ssize_t *received_len,
    const struct sockaddr_in *peer_addr
) {
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    *received_len = recvfrom(sockfd, buf, buf_size, 0, (struct sockaddr *)&src_addr, &src_len);
    if (*received_len < 0) {
        return -1;
    }

    if (src_addr.sin_addr.s_addr != peer_addr->sin_addr.s_addr || src_addr.sin_port != peer_addr->sin_port) {
        send_error_packet(sockfd, &src_addr, src_len, TFTP_ERR_UNKNOWN_TID, "Unknown transfer ID");
        errno = EPROTO;
        return -2;
    }

    return 0;
}

static int parse_request(const uint8_t *packet, ssize_t len, struct request_info *req) {
    memset(req, 0, sizeof(*req));

    if (len < 4) {
        return -1;
    }

    req->opcode = read_u16(packet);
    if (req->opcode != TFTP_RRQ && req->opcode != TFTP_WRQ) {
        return -1;
    }

    size_t index = 2;
    size_t filename_len = bounded_strlen((const char *)(packet + index), (size_t)len - index);
    if (index + filename_len >= (size_t)len || filename_len == 0 || filename_len >= sizeof(req->filename)) {
        return -1;
    }

    memcpy(req->filename, packet + index, filename_len);
    req->filename[filename_len] = '\0';
    index += filename_len + 1;

    size_t mode_len = bounded_strlen((const char *)(packet + index), (size_t)len - index);
    if (index + mode_len >= (size_t)len || mode_len == 0 || mode_len >= sizeof(req->mode)) {
        return -1;
    }

    memcpy(req->mode, packet + index, mode_len);
    req->mode[mode_len] = '\0';

    if (strcasecmp(req->mode, "octet") != 0 && strcasecmp(req->mode, "netascii") != 0) {
        return -2;
    }

    index += mode_len + 1;

    while (index < (size_t)len) {
        char option[32];
        char value[32];
        uint64_t parsed = 0;
        size_t option_len = bounded_strlen((const char *)(packet + index), (size_t)len - index);
        if (option_len == 0 || index + option_len >= (size_t)len || option_len >= sizeof(option)) {
            return -1;
        }

        memcpy(option, packet + index, option_len);
        option[option_len] = '\0';
        index += option_len + 1;

        size_t value_len = bounded_strlen((const char *)(packet + index), (size_t)len - index);
        if (value_len == 0 || index + value_len >= (size_t)len || value_len >= sizeof(value)) {
            return -1;
        }

        memcpy(value, packet + index, value_len);
        value[value_len] = '\0';
        index += value_len + 1;

        if (strcasecmp(option, "tsize") == 0) {
            if (parse_u64(value, &parsed) < 0) {
                return -1;
            }
            req->has_tsize = true;
            req->tsize = parsed;
            continue;
        }

        if (strcasecmp(option, "blksize") == 0) {
            if (parse_u64(value, &parsed) < 0 || parsed < TFTP_MIN_BLKSIZE || parsed > TFTP_MAX_BLKSIZE) {
                return -1;
            }
            req->has_blksize = true;
            req->blksize = (uint16_t)parsed;
            continue;
        }

        if (strcasecmp(option, "timeout") == 0) {
            if (parse_u64(value, &parsed) < 0 || parsed == 0 || parsed > UINT8_MAX) {
                return -1;
            }
            req->has_timeout = true;
            req->timeout = (uint8_t)parsed;
            continue;
        }
    }

    return 0;
}

static int send_ack(int sockfd, const struct sockaddr_in *client_addr, socklen_t client_len, uint16_t block) {
    uint8_t packet[4];
    write_u16(packet, TFTP_ACK);
    write_u16(packet + 2, block);

    return sendto(sockfd, packet, sizeof(packet), 0, (const struct sockaddr *)client_addr, client_len);
}

static int send_data(
    int sockfd,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    uint16_t block,
    const uint8_t *data,
    size_t data_len
) {
    uint8_t *packet = malloc(4 + data_len);
    if (packet == NULL) {
        errno = ENOMEM;
        return -1;
    }

    if (data_len > TFTP_MAX_BLKSIZE) {
        errno = EINVAL;
        free(packet);
        return -1;
    }

    write_u16(packet, TFTP_DATA);
    write_u16(packet + 2, block);
    memcpy(packet + 4, data, data_len);

    ssize_t sent = sendto(sockfd, packet, 4 + data_len, 0, (const struct sockaddr *)client_addr, client_len);
    free(packet);
    return sent;
}

static int handle_rrq(
    int sockfd,
    const struct request_info *req,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const char *path,
    const char *filename
) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_NOT_FOUND, "File not found");
        } else {
            send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_ACCESS, "Unable to open file");
        }
        return -1;
    }

    struct stat st;
    bool has_total_bytes = false;
    uint64_t total_bytes = 0;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0) {
        has_total_bytes = true;
        total_bytes = (uint64_t)st.st_size;
    }

    uint8_t oack_packet[TFTP_OACK_PACKET_SIZE];
    size_t oack_len = 0;
    size_t block_size = TFTP_DEFAULT_DATA_SIZE;
    int timeout_sec = TFTP_DEFAULT_TIMEOUT_SEC;
    if (maybe_accept_options_for_rrq(
            req,
            has_total_bytes,
            total_bytes,
            oack_packet,
            sizeof(oack_packet),
            &oack_len,
            &block_size,
            &timeout_sec
        ) < 0) {
        close(fd);
        return -1;
    }

    if (set_socket_timeout(sockfd, timeout_sec) < 0) {
        close(fd);
        return -1;
    }

    uint8_t *data = malloc(block_size);
    uint8_t *ack_packet = malloc(block_size + 4);
    if (data == NULL || ack_packet == NULL) {
        free(data);
        free(ack_packet);
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    struct transfer_meter meter;
    init_transfer_meter(&meter, "download", filename, has_total_bytes, total_bytes);
    bool use_netascii = request_uses_netascii(req);
    struct netascii_encode_state netascii_state;
    if (use_netascii) {
        init_netascii_encode_state(&netascii_state);
    }

    if (oack_len > 0) {
        int retries = 0;
        while (retries < TFTP_RETRIES) {
            if (send_oack_packet(sockfd, client_addr, client_len, oack_packet, oack_len) < 0) {
                free(data);
                free(ack_packet);
                close(fd);
                return -1;
            }

            ssize_t recv_len = 0;
            int recv_status = recv_expected_packet(sockfd, ack_packet, block_size + 4, &recv_len, client_addr);
            if (recv_status == -2) {
                continue;
            }
            if (recv_status < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    retries++;
                    continue;
                }
                free(data);
                free(ack_packet);
                close(fd);
                return -1;
            }

            if (recv_len == 4 && read_u16(ack_packet) == TFTP_ACK && read_u16(ack_packet + 2) == 0) {
                break;
            }

            if (recv_len >= 4 && read_u16(ack_packet) == TFTP_ERROR) {
                free(data);
                free(ack_packet);
                close(fd);
                return -1;
            }
        }

        if (retries == TFTP_RETRIES) {
            free(data);
            free(ack_packet);
            close(fd);
            return -1;
        }
    }

    uint16_t block = 1;
    bool done = false;

    while (!done) {
        ssize_t bytes_read = use_netascii
            ? read_netascii_block(fd, &netascii_state, data, block_size)
            : read(fd, data, block_size);
        if (bytes_read < 0) {
            send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_UNDEFINED, "Read failure");
            free(data);
            free(ack_packet);
            close(fd);
            return -1;
        }

        int retries = 0;
        while (retries < TFTP_RETRIES) {
            if (send_data(sockfd, client_addr, client_len, block, data, (size_t)bytes_read) < 0) {
                free(data);
                free(ack_packet);
                close(fd);
                return -1;
            }

            ssize_t recv_len = 0;
            int recv_status = recv_expected_packet(sockfd, ack_packet, block_size + 4, &recv_len, client_addr);
            if (recv_status == -2) {
                continue;
            }
            if (recv_status < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    retries++;
                    continue;
                }
                free(data);
                free(ack_packet);
                close(fd);
                return -1;
            }

            if (recv_len == 4 && read_u16(ack_packet) == TFTP_ACK && read_u16(ack_packet + 2) == block) {
                break;
            }

            if (recv_len >= 4 && read_u16(ack_packet) == TFTP_ERROR) {
                free(data);
                free(ack_packet);
                close(fd);
                return -1;
            }
        }

        if (retries == TFTP_RETRIES) {
            free(data);
            free(ack_packet);
            close(fd);
            return -1;
        }

        done = (size_t)bytes_read < block_size;
        log_transfer_progress(client_addr, &meter, (size_t)bytes_read, done);
        block++;
    }

    free(data);
    free(ack_packet);
    close(fd);
    return 0;
}

static int handle_wrq(
    int sockfd,
    const struct request_info *req,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const char *path,
    const char *filename
) {
    char temp_path[576];
    int fd = open_upload_temp_file(path, temp_path, sizeof(temp_path));
    if (fd < 0) {
        send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_ACCESS, "Unable to create upload file");
        return -1;
    }

    uint8_t oack_packet[TFTP_OACK_PACKET_SIZE];
    size_t oack_len = 0;
    size_t block_size = TFTP_DEFAULT_DATA_SIZE;
    int timeout_sec = TFTP_DEFAULT_TIMEOUT_SEC;
    bool has_total_bytes = false;
    uint64_t total_bytes = 0;
    if (maybe_accept_options_for_wrq(
            req,
            oack_packet,
            sizeof(oack_packet),
            &oack_len,
            &block_size,
            &timeout_sec,
            &has_total_bytes,
            &total_bytes
        ) < 0) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    if (set_socket_timeout(sockfd, timeout_sec) < 0) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    if (oack_len > 0) {
        if (send_oack_packet(sockfd, client_addr, client_len, oack_packet, oack_len) < 0) {
            close(fd);
            unlink(temp_path);
            return -1;
        }
    } else if (send_ack(sockfd, client_addr, client_len, 0) < 0) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    uint16_t expected_block = 1;
    uint8_t *packet = malloc(block_size + 4);
    uint8_t *decoded = NULL;
    if (packet == NULL) {
        close(fd);
        unlink(temp_path);
        errno = ENOMEM;
        return -1;
    }

    bool use_netascii = request_uses_netascii(req);
    struct netascii_decode_state netascii_state = {0};
    if (use_netascii) {
        decoded = malloc(block_size + 1);
        if (decoded == NULL) {
            free(packet);
            close(fd);
            unlink(temp_path);
            errno = ENOMEM;
            return -1;
        }
    }

    struct transfer_meter meter;
    init_transfer_meter(&meter, "upload", filename, has_total_bytes, total_bytes);

    for (;;) {
        int retries = 0;
        ssize_t recv_len = 0;

        while (retries < TFTP_RETRIES) {
            int recv_status = recv_expected_packet(sockfd, packet, block_size + 4, &recv_len, client_addr);
            if (recv_status == -2) {
                continue;
            }
            if (recv_status < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (oack_len > 0 && expected_block == 1) {
                        if (send_oack_packet(sockfd, client_addr, client_len, oack_packet, oack_len) < 0) {
                            free(packet);
                            close(fd);
                            unlink(temp_path);
                            return -1;
                        }
                    } else if (send_ack(sockfd, client_addr, client_len, (uint16_t)(expected_block - 1)) < 0) {
                        free(packet);
                        close(fd);
                        unlink(temp_path);
                        return -1;
                    }
                    retries++;
                    continue;
                }
                free(packet);
                close(fd);
                unlink(temp_path);
                return -1;
            }

            break;
        }

        if (retries == TFTP_RETRIES) {
            free(decoded);
            free(packet);
            close(fd);
            unlink(temp_path);
            return -1;
        }

        if (recv_len < 4 || read_u16(packet) != TFTP_DATA) {
            send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_ILLEGAL_OP, "Expected DATA packet");
            free(decoded);
            free(packet);
            close(fd);
            unlink(temp_path);
            return -1;
        }

        uint16_t block = read_u16(packet + 2);
        if (block == expected_block) {
            ssize_t data_len = recv_len - 4;
            const uint8_t *to_write = packet + 4;
            size_t write_len = (size_t)data_len;

            if (use_netascii) {
                ssize_t decoded_len = decode_netascii_chunk(
                    &netascii_state,
                    packet + 4,
                    (size_t)data_len,
                    (size_t)data_len < block_size,
                    decoded,
                    block_size + 1
                );
                if (decoded_len < 0) {
                    send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_UNDEFINED, "Netascii decode failure");
                    free(decoded);
                    free(packet);
                    close(fd);
                    unlink(temp_path);
                    return -1;
                }
                to_write = decoded;
                write_len = (size_t)decoded_len;
            }

            if (write_all(fd, to_write, write_len) < 0) {
                send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_DISK_FULL, "Write failure");
                free(decoded);
                free(packet);
                close(fd);
                unlink(temp_path);
                return -1;
            }

            if ((size_t)data_len < block_size) {
                if (close(fd) < 0) {
                    free(decoded);
                    free(packet);
                    unlink(temp_path);
                    return -1;
                }
                fd = -1;

                if (rename(temp_path, path) < 0) {
                    send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_ACCESS, "Unable to replace target file");
                    free(decoded);
                    free(packet);
                    unlink(temp_path);
                    return -1;
                }

                if (send_ack(sockfd, client_addr, client_len, block) < 0) {
                    free(decoded);
                    free(packet);
                    return -1;
                }

                log_transfer_progress(client_addr, &meter, write_len, true);
                break;
            }

            if (send_ack(sockfd, client_addr, client_len, block) < 0) {
                free(decoded);
                free(packet);
                close(fd);
                unlink(temp_path);
                return -1;
            }

            log_transfer_progress(client_addr, &meter, write_len, false);
            expected_block++;
            continue;
        }

        if (block == (uint16_t)(expected_block - 1)) {
            if (send_ack(sockfd, client_addr, client_len, block) < 0) {
                free(decoded);
                free(packet);
                close(fd);
                unlink(temp_path);
                return -1;
            }
            continue;
        }

        send_error_packet(sockfd, client_addr, client_len, TFTP_ERR_ILLEGAL_OP, "Unexpected block number");
        free(decoded);
        free(packet);
        close(fd);
        unlink(temp_path);
        return -1;
    }

    if (fd >= 0) {
        close(fd);
    }
    free(decoded);
    free(packet);
    return 0;
}

static void handle_request(
    const struct request_info *req,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const char *path
) {
    int transfer_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (transfer_sock < 0) {
        return;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(0);

    if (bind(transfer_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        close(transfer_sock);
        return;
    }

    if (set_socket_timeout(transfer_sock, TFTP_DEFAULT_TIMEOUT_SEC) < 0) {
        close(transfer_sock);
        return;
    }

    if (req->opcode == TFTP_RRQ) {
        handle_rrq(transfer_sock, req, client_addr, client_len, path, req->filename);
    } else {
        handle_wrq(transfer_sock, req, client_addr, client_len, path, req->filename);
    }

    close(transfer_sock);
}

int main(int argc, char *argv[]) {
    const char *root_dir = "./data";
    uint16_t listen_port = TFTP_PORT;

    if (argc > 3) {
        fprintf(stderr, "Usage: %s [root_dir] [port]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc >= 2) {
        root_dir = argv[1];
    }
    if (argc == 3 && parse_port(argv[2], &listen_port) < 0) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    if (mkdir(root_dir, 0755) < 0 && errno != EEXIST) {
        perror("mkdir");
        return EXIT_FAILURE;
    }

    struct sigaction sa_term;
    memset(&sa_term, 0, sizeof(sa_term));
    sa_term.sa_handler = handle_signal;
    sigemptyset(&sa_term.sa_mask);
    sigaction(SIGINT, &sa_term, NULL);
    sigaction(SIGTERM, &sa_term, NULL);

    struct sigaction sa_chld;
    memset(&sa_chld, 0, sizeof(sa_chld));
    sa_chld.sa_handler = reap_children;
    sa_chld.sa_flags = SA_RESTART;
    sigemptyset(&sa_chld.sa_mask);
    sigaction(SIGCHLD, &sa_chld, NULL);

    int server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_sock);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(listen_port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        fprintf(stderr, "Binding UDP port %u may require additional privileges.\n", listen_port);
        close(server_sock);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "TFTP server listening on udp/%u, root directory: %s\n", listen_port, root_dir);

    while (g_running) {
        uint8_t packet[TFTP_REQUEST_PACKET_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        ssize_t packet_len = recvfrom(
            server_sock,
            packet,
            sizeof(packet),
            0,
            (struct sockaddr *)&client_addr,
            &client_len
        );

        if (packet_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            break;
        }

        struct request_info req;
        int parse_status = parse_request(packet, packet_len, &req);
        if (parse_status == -2) {
            send_error_packet(server_sock, &client_addr, client_len, TFTP_ERR_ILLEGAL_OP, "Supported modes: octet, netascii");
            log_client(&client_addr, "rejected request with unsupported mode");
            continue;
        }
        if (parse_status < 0) {
            send_error_packet(server_sock, &client_addr, client_len, TFTP_ERR_ILLEGAL_OP, "Malformed request");
            log_client(&client_addr, "rejected malformed request");
            continue;
        }

        if (!is_safe_filename(req.filename)) {
            send_error_packet(server_sock, &client_addr, client_len, TFTP_ERR_ACCESS, "Unsafe filename");
            log_client(&client_addr, "rejected unsafe filename");
            continue;
        }

        char path[512];
        if (build_path(path, sizeof(path), root_dir, req.filename) < 0) {
            send_error_packet(server_sock, &client_addr, client_len, TFTP_ERR_ACCESS, "Path too long");
            log_client(&client_addr, "rejected overlong path");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            continue;
        }

        if (pid == 0) {
            close(server_sock);
            handle_request(&req, &client_addr, client_len, path);
            _exit(EXIT_SUCCESS);
        }

        char message[320];
        snprintf(message, sizeof(message), "accepted %s for %s", req.opcode == TFTP_RRQ ? "RRQ" : "WRQ", req.filename);
        log_client(&client_addr, message);
    }

    close(server_sock);
    return EXIT_SUCCESS;
}
