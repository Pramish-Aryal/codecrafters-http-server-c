#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base.h"

const char* global_directory_path = NULL;

String read_entire_file(Arena* arena, const char* filename)
{
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return (String) {};
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(file);
        return (String) {};
    }

    long size = ftell(file);
    if (size < 0) {
        perror("ftell");
        fclose(file);
        return (String) {};
    }
    rewind(file);

    char* buffer = (char*)arena_alloc(arena, size + 1);
    if (!buffer) {
        perror("arena_alloc failed");
        fclose(file);
        return (String) {};
    }

    size_t read_size = fread(buffer, 1, size, file);
    if (read_size != (size_t)size) {
        perror("fread");
        free(buffer);
        fclose(file);
        return (String) {};
    }

    buffer[size] = '\0';
    fclose(file);

    return (String) {
        .data = buffer,
        .len = size,
        .capacity = size,
    };
}

bool write_entire_file(const char* filename, StringView sv)
{
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("fopen");
        return false;
    }

    size_t written = fwrite(sv.data, 1, sv.len, file);
    if (written != sv.len) {
        perror("fwrite");
        fclose(file);
        return false;
    }

    fclose(file);
    return true;
}
void* handle_socket_thread(void* arg)
{
    int client_fd = *(int*)arg;

    Arena arena_stack = { 0 };
    Arena* arena = &arena_stack;
    u32 backing_buffer_len = MB(1);
    char* backing_buffer = malloc(backing_buffer_len);
    arena_init(arena, backing_buffer, backing_buffer_len);

    u32 client_buffer_size = 1024;
    char* client_buffer = arena_alloc(arena, client_buffer_size);
    int bytes_read = read(client_fd, client_buffer, client_buffer_size);

    // assume bytes_read < client_buffer_size -1;
    client_buffer[bytes_read] = 0; // null terminate (though its unnecessary as arena_alloc returns a null terminated buffer)
    StringView http_request = sv_from_cstr(client_buffer);
    StringView iter = http_request;

    // format to parse: GET /index.html HTTP/1.1\r\nHost: localhost:4221\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n
    StringView request_line = sv_chop_by_delim(&iter, '\n');
    printf("request-line: " SV_Fmt "\n", SV_Arg(request_line));
    StringView http_method = sv_chop_by_delim(&request_line, ' '); // GET
    StringView request_target = sv_chop_by_delim(&request_line, ' '); // /index.html
    StringView http_version = sv_chop_by_delim(&request_line, ' '); // HTTP/1.1
    assert(sv_trim(request_line).len == 0 && "request line must have been fully parsed");

    HashTable headers = { 0 };
    hash_table_init(arena, &headers);
    StringView header_line = sv_trim(sv_chop_by_delim(&iter, '\n'));
    while (header_line.len != 0) {
        StringView header_key = sv_chop_by_delim(&header_line, ':');
        StringView header_value = sv_trim(header_line);
        String lower_case_key = sv_to_owned(arena, header_key);
        string_to_lower(lower_case_key);
        hash_table_set(&headers, string_to_sv(lower_case_key), sv_to_owned(arena, header_value).data);
        header_line = sv_trim(sv_chop_by_delim(&iter, '\n'));
    }

    printf("\nhttp_method: " SV_Fmt "\nrequest_target:" SV_Fmt "\nhttp_version: " SV_Fmt "\n\n", SV_Arg(http_method), SV_Arg(request_target), SV_Arg(http_version));

    String return_buffer;
    StringView echo = sv_from_cstr("/echo/");
    StringView files = sv_from_cstr("/files/");
    if (sv_eq(request_target, sv_from_cstr("/"))) {
        StringView response_200 = sv_from_cstr("HTTP/1.1 200 OK\r\n\r\n");
        return_buffer = sv_to_owned(arena, response_200);
    } else if (sv_starts_with(request_target, files)) {
        if (global_directory_path == NULL) {
            StringView response_404 = sv_from_cstr("HTTP/1.1 404 Not Found\r\n\r\n");
            return_buffer = sv_to_owned(arena, response_404);
        } else {
            StringView files_ = sv_chop_left(&request_target, files.len);
            assert(sv_eq(files, files_));
            return_buffer = (String) {
                .data = arena_alloc(arena, KB(256)),
                .capacity = KB(256),
                .len = 0,
            };

            StringView target_file = sv_trim(request_target);
            String file_path = (String) {
                .data = arena_alloc(arena, 256),
                .capacity = 256,
            };
            string_concat(&file_path, sv_from_cstr(global_directory_path));
            string_concat(&file_path, target_file); // assume file_path is null terminated because file_path is originally filled with zero bytes

            if (sv_eq(http_method, sv_from_cstr("GET"))) {
                String file = read_entire_file(arena, file_path.data);
                if (file.len == 0) {
                    StringView response_404 = sv_from_cstr("HTTP/1.1 404 Not Found\r\n\r\n");
                    return_buffer = sv_to_owned(arena, response_404);
                } else {
                    return_buffer.len = snprintf(return_buffer.data, return_buffer.capacity, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n" SV_Fmt, (int)file.len, SV_Arg(file));
                }
            } else if (sv_eq(http_method, sv_from_cstr("POST"))) {
                StringView content_length_str = sv_from_cstr(hash_table_get(&headers, sv_from_cstr("content-length")));
                int content_length = sv_chop_u64(&content_length_str);
                StringView content = sv_from_parts(iter.data, content_length);
                write_entire_file(file_path.data, content);
                StringView response_201 = sv_from_cstr("HTTP/1.1 201 Created\r\n\r\n");
                return_buffer = sv_to_owned(arena, response_201);
            } else {
                StringView response_400 = sv_from_cstr("HTTP/1.1 400 Bad Request\r\n\r\n");
                return_buffer = sv_to_owned(arena, response_400);
            }
        }
    } else if (sv_eq(request_target, sv_from_cstr("/user-agent"))) {
        const char* user_agent_cstr = hash_table_get(&headers, sv_from_cstr("user-agent"));
        StringView user_agent = sv_from_cstr(user_agent_cstr);
        return_buffer = (String) {
            .data = arena_alloc(arena, 1024),
            .capacity = 1024,
        };
        return_buffer.len = snprintf(return_buffer.data, return_buffer.capacity, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" SV_Fmt, (int)user_agent.len, SV_Arg(user_agent));
    } else if (sv_starts_with(request_target, echo)) {
        StringView echo_ = sv_chop_left(&request_target, echo.len);
        assert(sv_eq(echo, echo_));
        return_buffer = (String) {
            .data = arena_alloc(arena, 1024),
            .capacity = 1024,
        };

        return_buffer.len = snprintf(return_buffer.data, return_buffer.capacity, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" SV_Fmt, (int)request_target.len, SV_Arg(request_target));
    } else {
        StringView response_404 = sv_from_cstr("HTTP/1.1 404 Not Found\r\n\r\n");
        return_buffer = sv_to_owned(arena, response_404);
    }

    write(client_fd, return_buffer.data, return_buffer.len);

    close(client_fd);
    free(backing_buffer);

    return NULL;
}

int main(int argc, char** argv)
{
    Arena arena_stack = { 0 };
    Arena* arena = &arena_stack;
    u32 backing_buffer_len = KB(16);
    char* backing_buffer = malloc(backing_buffer_len);
    arena_init(arena, backing_buffer, backing_buffer_len);

    for (int i = 0; i < argc;) {
        StringView arg = sv_from_cstr(argv[i]);
        if (sv_eq(arg, sv_from_cstr("--directory"))) {
            i++;
            global_directory_path = argv[i];
        }
        i++;
    }

    if (global_directory_path == NULL) {
        global_directory_path = "/tmp/";
    }

    ThreadPool* pool = pool_init(arena, 10);

    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("Logs from your program will appear here!\n");

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        printf("Socket creation failed: %s...\n", strerror(errno));
        return 1;
    }

    // Since the tester restarts your program quite often, setting SO_REUSEADDR
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        printf("SO_REUSEADDR failed: %s \n", strerror(errno));
        return 1;
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(4221),
        .sin_addr = { htonl(INADDR_ANY) },
    };

    if (bind(server_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
        printf("Bind failed: %s \n", strerror(errno));
        return 1;
    }

    int connection_backlog = 5;
    if (listen(server_fd, connection_backlog) != 0) {
        printf("Listen failed: %s \n", strerror(errno));
        return 1;
    }

    printf("Waiting for a client to connect...\n");

    for (;;) {
        struct sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        printf("New client connected\n");

        int* arg = arena_alloc(arena, sizeof(*arg));
        *arg = client_fd;

        pool_add_task(pool, handle_socket_thread, arg);
    }

    // de-init
    close(server_fd);
    pool_destroy(pool);
    free(backing_buffer);
    return 0;
}
