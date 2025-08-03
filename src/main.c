#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base.h"

int main()
{
    Arena arena_stack = { 0 };
    Arena* arena = &arena_stack;
    u32 backing_buffer_len = KB(16);
    char* backing_buffer = malloc(backing_buffer_len);
    arena_init(arena, backing_buffer, backing_buffer_len);

    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("Logs from your program will appear here!\n");

    int server_fd, client_addr_len;
    struct sockaddr_in client_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
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
    client_addr_len = sizeof(client_addr);

    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    printf("Client connected\n");

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
    while (iter.len != 0) {
        StringView header_line = sv_chop_by_delim(&iter, '\n');
        StringView header_key = sv_chop_by_delim(&header_line, ':');
        StringView header_value = sv_trim(header_line);
        String lower_case_key = sv_to_owned(arena, header_key);
        string_to_lower(lower_case_key);
        hash_table_set(&headers, string_to_sv(lower_case_key), sv_to_owned(arena, header_value).data);
    }

    printf("\nhttp_method: " SV_Fmt "\nrequest_target:" SV_Fmt "\nhttp_version: " SV_Fmt "\n\n", SV_Arg(http_method), SV_Arg(request_target), SV_Arg(http_version));

    String return_buffer;
    StringView echo = sv_from_cstr("/echo/");
    if (sv_eq(request_target, sv_from_cstr("/"))) {
        StringView response_200 = sv_from_cstr("HTTP/1.1 200 OK\r\n\r\n");
        return_buffer = sv_to_owned(arena, response_200);
    } else if (sv_eq(request_target, sv_from_cstr("/user-agent"))) {
        const char* user_agent_cstr = hash_table_get(&headers, sv_from_cstr("user-agent"));
        StringView user_agent = sv_from_cstr(user_agent_cstr);
        return_buffer = (String) {
            .data = arena_alloc(arena, 1024),
            .len = 1024,
        };
        int written_bytes = snprintf(return_buffer.data, return_buffer.len, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" SV_Fmt, (int)user_agent.len, SV_Arg(user_agent));
        return_buffer.len = written_bytes;
    } else if (sv_starts_with(request_target, echo)) {
        StringView echo_ = sv_chop_left(&request_target, echo.len);
        assert(sv_eq(echo, echo_));
        return_buffer = (String) {
            .data = arena_alloc(arena, 1024),
            .len = 1024,
        };

        int written_bytes = snprintf(return_buffer.data, return_buffer.len, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" SV_Fmt, (int)request_target.len, SV_Arg(request_target));
        return_buffer.len = written_bytes;
    } else {
        StringView response_404 = sv_from_cstr("HTTP/1.1 404 Not Found\r\n\r\n");
        return_buffer = sv_to_owned(arena, response_404);
    }

    write(client_fd, return_buffer.data, return_buffer.len);

    // de-init
    close(client_fd);
    close(server_fd);
    free(backing_buffer);
    return 0;
}
