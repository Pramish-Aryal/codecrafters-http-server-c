#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define ENABLE_GZIP

#ifdef ENABLE_GZIP // GZIP is disabled by default because CMAKE takes a bit too long to build the program otherwise
#include <zlib.h>
#endif

#include "base.h"

const char* global_directory_path = NULL;

String read_entire_file_arena(Arena* arena, const char* filename)
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

#ifdef ENABLE_GZIP
#define GZIP_CHUNK 16384
String gzip_compress_sv(Arena* arena, StringView input)
{
    String result = { 0 };
    z_stream strm = { 0 };
    int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY); // 15+16 enables gzip headers
    if (ret != Z_OK)
        return result;

    strm.avail_in = input.len;
    strm.next_in = (Bytef*)input.data;

    do {
        vec_ensure_cap(arena, &result, result.len + GZIP_CHUNK);

        strm.avail_out = result.capacity - result.len;
        strm.next_out = (Bytef*)(result.data + result.len);

        ret = deflate(&strm, Z_FINISH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            deflateEnd(&strm);
            result.len = 0;
            return result;
        }
        result.len = result.capacity - strm.avail_out;
    } while (ret != Z_STREAM_END);

    deflateEnd(&strm);
    return result;
}

String gunzip_decompress_dynamic(Arena* arena, StringView input)
{
    String out = { 0 };

    z_stream strm = { 0 };
    int ret = inflateInit2(&strm, 15 + 16); // 15+16 enables gzip decoding
    if (ret != Z_OK)
        return out;

    strm.avail_in = input.len;
    strm.next_in = (Bytef*)input.data;

    do {
        vec_ensure_cap(arena, &out, out.len + GZIP_CHUNK);

        strm.avail_out = out.capacity - out.len;
        strm.next_out = (Bytef*)(out.data + out.len);

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&strm);
            out.len = 0; // Clear on error
            return out;
        }

        out.len = out.capacity - strm.avail_out;
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return out;
}
#endif

#define CONTENT_LENGTH_SV SV_STATIC("content-length")
#define ACCEPT_ENCODING_SV SV_STATIC("accept-encoding")
#define CONTENT_ENCODING_SV SV_STATIC("content-encoding")
#define CONTENT_TYPE_SV SV_STATIC("content-type")
#define USER_AGENT_SV SV_STATIC("user-agent")

typedef struct HttpRequest {
    String method;
    String route;
    String version;
    HashTable headers;
    HashTable query_params;
    HashTable route_params;
    String body;
    bool keep_alive;
} HttpRequest;

typedef struct HttpResponse {
    int client_socket;
} HttpResponse;

size_t write_string(HttpResponse* r, StringView str)
{
    return send(r->client_socket, str.data, str.len, 0);
}

void write_all_bytes(HttpResponse* r, StringView str)
{
    while (str.len > 0) {
        size_t sent = write_string(r, str);
        str.data += sent;
        str.len -= sent;
    }
}

bool parse_http_request(Arena* arena, HttpRequest* request, StringView* http_request_str)
{
    StringView request_line = sv_chop_by_delim(http_request_str, '\n');
    printf("request-line: " SV_Fmt "\n", SV_Arg(request_line));
    StringView http_method = sv_chop_by_delim(&request_line, ' '); // GET
    StringView request_target = sv_chop_by_delim(&request_line, ' '); // /index.html
    StringView http_version = sv_chop_by_delim(&request_line, ' '); // HTTP/1.1

    request->method = sv_to_owned(arena, http_method);
    request->route = sv_to_owned(arena, request_target);
    request->version = sv_to_owned(arena, http_version);
    assert(sv_trim(request_line).len == 0 && "request line must have been fully parsed");

    request->headers = (HashTable) { 0 };
    request->query_params = (HashTable) { 0 };
    request->route_params = (HashTable) { 0 };
    hash_table_init(arena, &request->headers);
    hash_table_init(arena, &request->query_params);
    hash_table_init(arena, &request->route_params);
    StringView header_line = sv_trim(sv_chop_by_delim(http_request_str, '\n'));
    while (header_line.len != 0) {
        StringView header_key = sv_chop_by_delim(&header_line, ':');
        StringView header_value = sv_trim(header_line);
        String lower_case_key = sv_to_owned(arena, header_key);
        string_to_lower(lower_case_key);
        hash_table_set(&request->headers, string_to_sv(lower_case_key), sv_to_owned(arena, header_value).data);
        header_line = sv_trim(sv_chop_by_delim(http_request_str, '\n'));
    }
}

typedef void HandlerFunc(Arena*, HttpRequest*, HttpResponse*);

typedef struct RouteMapping {
    // String method;   // TODO(pramish): add ability to add methods in the mapping as well
    StringView route;
    HandlerFunc* handler;
} RouteMapping; //  TODO(pramish): this should really be a part of a hashtable

typedef struct RouteMappings {
    int len;
    RouteMapping* data;
} RouteMappings;

typedef struct Server {
    int client_fd;
    RouteMappings mappings;
    HandlerFunc* default_404_handler;
} Server;

typedef struct Segments {
    StringView* data;
    int len;
    int capacity;
} Segments;

int compute_specificity(StringView path)
{
    int score = 0;
    sv_chop_by_delim(&path, '/');
    StringView token = sv_chop_by_delim(&path, '/');
    while (token.len > 0) {
        if (token.data[0] == ':')
            score += 1; // param
        else
            score += 10; // static
        token = sv_chop_by_delim(&path, '/');
    }
    return score;
}

Segments split_segments(Arena* arena, StringView path)
{
    Segments segments = { 0 };
    sv_chop_by_delim(&path, '/'); // skip the first '/'

    StringView segment = sv_chop_by_delim(&path, '/');
    while (segment.len != 0) {
        vec_append(arena, &segments, segment);
        segment = sv_chop_by_delim(&path, '/');
    }
    return segments;
}

void* handle_socket_thread(void* arg)
{
    Server* server = (Server*)arg;
    int client_fd = server->client_fd;

    Arena arena_stack = { 0 };
    Arena* arena = &arena_stack;
    u32 backing_buffer_len = MB(1);
    char* backing_buffer = malloc(backing_buffer_len);

    struct pollfd pfd = { 0 };

    pfd.fd = client_fd;
    pfd.events = POLLIN;

    bool keep_alive = true;

    while (keep_alive) {

        // 10 sec timeout
        int ret = poll(&pfd, 1, 10000);
        if (ret < 0) {
            perror("poll error");
            break;
        } else if (ret == 0) {
            printf("poll: client timeout\n");
            break;
        }

        if (pfd.revents & POLLIN) {
            arena_init(arena, backing_buffer, backing_buffer_len);

            String temp_buffer = { 0 };
            vec_ensure_cap(arena, &temp_buffer, 1024);
            String client_buffer = { 0 };
            i32 bytes_read;
            i32 total_bytes_read = 0;

            i32 header_end = -1;
            // easier to split the request header + body parsing in two phases, first just the body as such,
            while ((bytes_read = recv(client_fd, temp_buffer.data, (int)temp_buffer.capacity, 0)) > 0) {
                vec_append_many(arena, &client_buffer, temp_buffer.data, bytes_read);
                total_bytes_read += bytes_read;

                // Search for end of headers: "\r\n\r\n"
                for (i32 i = 0; i < (client_buffer.len - 3); ++i) {
                    if (memcmp(client_buffer.data + i, "\r\n\r\n", 4) == 0) {
                        header_end = i + 4; // body starts after this
                        goto headers_done;
                    }
                }
            }

        headers_done:
            if (header_end == -1) {
                printf("Malformed request: no header terminator found.\n");
                break;
            }

            StringView request_view = string_to_sv(client_buffer);
            HttpRequest request = {};
            parse_http_request(arena, &request, &request_view); // must extract content_length

            // close socket after this request
            {
                const char* connection_str = hash_table_get(&request.headers, SV_STATIC("Connection"));
                if (connection_str) {
                    StringView connection = sv_from_cstr(connection_str);
                    if (sv_eq(connection, SV_STATIC("close"))) {
                        keep_alive = false;
                    }
                }
            }

            request.keep_alive = keep_alive;

            // parse the body in a second phase because its easier to track how much we need to read after
            // reading the content-length header
            {
                const char* content_length_cstr = hash_table_get(&request.headers, CONTENT_LENGTH_SV);
                if (content_length_cstr) {
                    StringView content_length_str = sv_from_cstr(content_length_cstr);
                    int content_length = sv_chop_u64(&content_length_str);

                    i32 body_bytes_needed = content_length;
                    size_t body_start = header_end;

                    while (client_buffer.len < body_start + body_bytes_needed) {
                        bytes_read = recv(client_fd, temp_buffer.data, (int)temp_buffer.capacity, 0);
                        if (bytes_read <= 0) {
                            printf("Client disconnected or error while reading body\n");
                            break;
                        }

                        vec_append_many(arena, &client_buffer, temp_buffer.data, bytes_read);
                        total_bytes_read += bytes_read;
                    }

                    StringView content = sv_from_parts(request_view.data, content_length);
                    request.body = sv_to_owned(arena, content);
                }
            }

            HttpResponse response;
            response.client_socket = client_fd;

            bool mapping_found = false;
            RouteMapping selected_mapping = { 0 };
            for (int i = 0; i < server->mappings.len; ++i) {
                if (mapping_found) {
                    break;
                }

                RouteMapping mapping = server->mappings.data[i];
                StringView route_sv = string_to_sv(request.route);
                StringView mapping_route = mapping.route;

                // NOTE: paths either need to match exactly, or have the same pathing params

                // /echo/:echo_path/:some_other_path/fixed_path // mapping path
                // /echo/path_to_echo/other_path/fixed_path // route path

                // if the path exactly matches, there is no need to do this I guess?
                if (sv_eq(route_sv, mapping_route)) {
                    // TODO: maybe validate if mapping route doesn't have any route params defined
                    selected_mapping = mapping;
                    mapping_found = true;
                    break;
                }

                Temp_Arena_Memory temp_arena = temp_arena_memory_begin(arena);

                Segments route_segments = split_segments(arena, route_sv);
                Segments mapping_route_segments = split_segments(arena, mapping_route);

                if (route_segments.len != mapping_route_segments.len)
                    continue;

                for (int i = 0; i < route_segments.len; ++i) {
                    StringView route_segment = route_segments.data[i];
                    StringView mapping_route_segment = mapping_route_segments.data[i];

                    if (sv_starts_with(mapping_route_segment, SV_STATIC(":"))) {
                        // do nothing, we'll do the assignments later
                    } else {
                        if (!sv_eq(route_segment, mapping_route_segment)) {
                            mapping_found = false;
                            break;
                        }
                    }

                    selected_mapping = mapping;
                    mapping_found = true;
                }

                temp_arena_memory_end(temp_arena);
            }

            if (mapping_found) {
                // redo the parsing and route_param setting
                StringView route_sv = string_to_sv(request.route);
                StringView mapping_route = selected_mapping.route;

                Segments route_segments = split_segments(arena, route_sv);
                Segments mapping_route_segments = split_segments(arena, mapping_route);

                for (int i = 0; i < route_segments.len; ++i) {
                    StringView route_segment = route_segments.data[i];
                    StringView mapping_route_segment = mapping_route_segments.data[i];

                    if (sv_starts_with(mapping_route_segment, SV_STATIC(":"))) {
                        sv_chop_left(&mapping_route_segment, 1);
                        StringView path_var = mapping_route_segment;
                        hash_table_set(&request.route_params, path_var, sv_to_owned(arena, route_segment).data);
                    }
                }
                assert(selected_mapping.handler && "Handler must be defined");
                selected_mapping.handler(arena, &request, &response);
            } else {
                if (server->default_404_handler) {
                    server->default_404_handler(arena, &request, &response);
                } else {
                    StringView not_found = SV_STATIC("HTTP/1.1 404 Not Found\r\n"
                                                     "Content-Type: text/html; charset=utf-8\r\n"
                                                     "Content-Length: 18\r\n"
                                                     "Connection: close\r\n"
                                                     "\r\n"
                                                     "<h1>Not found</h1>");
                    write_string(&response, not_found);
                }
            }
        }
    }

    close(client_fd);
    free(backing_buffer);
    free(arg);

    return NULL;
}

void handle_route_index(Arena* arena, HttpRequest* request, HttpResponse* response)
{
    if (sv_eq(string_to_sv(request->method), SV_STATIC("GET"))) {
        if (request->keep_alive) {
            StringView response_200 = SV_STATIC("HTTP/1.1 200 OK\r\n\r\n");
            write_string(response, response_200);
        } else {
            StringView response_200_closed = SV_STATIC("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
            write_string(response, response_200_closed);
        }
    } else {
        StringView response_405 = SV_STATIC("HTTP/1.1 405 Method Not Allowed\r\n"
                                            "Content-Type: text/html; charset=utf-8\r\n"
                                            "Content-Length: 27\r\n"
                                            "Connection: close\r\n"
                                            "\r\n"
                                            "<h1>Method Not Allowed</h1>");
        write_string(response, response_405);
    }
}

void handle_route_404(Arena* arena, HttpRequest* request, HttpResponse* response)
{
    if (request->keep_alive) {
        StringView response_404 = SV_STATIC("HTTP/1.1 404 Not Found\r\n\r\n");
        write_string(response, response_404);
    } else {
        StringView response_404_closed = SV_STATIC("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
        write_string(response, response_404_closed);
    }
}

void handle_route_user_agent(Arena* arena, HttpRequest* request, HttpResponse* response)
{
    const char* user_agent_cstr = hash_table_get(&request->headers, sv_from_cstr("user-agent"));
    StringView user_agent = sv_from_cstr(user_agent_cstr);
    String response_body = (String) {
        .data = arena_alloc(arena, 1024),
        .capacity = 1024,
    };
    response_body.len = snprintf(response_body.data, response_body.capacity, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n%s\r\n" SV_Fmt,
        (int)user_agent.len, request->keep_alive ? "Connection: close\r\n" : "", SV_Arg(user_agent));
    write_string(response, string_to_sv(response_body));
}

void handle_route_echo(Arena* arena, HttpRequest* request, HttpResponse* response)
{
    StringView accept_encodings = { 0 };
    const char* accept_encodings_cstr = hash_table_get(&request->headers, ACCEPT_ENCODING_SV);
    if (accept_encodings_cstr) {
        accept_encodings = sv_from_cstr(accept_encodings_cstr);
    };
    StringView echo = sv_from_cstr(hash_table_get(&request->route_params, SV_STATIC("echo")));

    bool gzip_found = false;
    if (accept_encodings.len > 0) {
        // we can have a multitude of accepted encodings
        StringView accept_encoding = sv_trim(sv_chop_by_delim(&accept_encodings, ','));
        while (accept_encoding.len > 0) {
            if (sv_eq(accept_encoding, SV_STATIC("gzip"))) {
                gzip_found = true;
                break;
            }
            accept_encoding = sv_trim(sv_chop_by_delim(&accept_encodings, ','));
        }
    }

    String response_body = (String) {
        .data = arena_alloc(arena, 1024),
        .capacity = 1024,
    };
    if (gzip_found) {
#ifdef ENABLE_GZIP
        String compressed_echo_owned = gzip_compress_sv(arena, echo);
        StringView compressed_echo = string_to_sv(compressed_echo_owned);
#else
        StringView compressed_echo = echo;
#endif
        response_body.len = snprintf(response_body.data, response_body.capacity, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n%s\r\n",
            (int)compressed_echo.len, request->keep_alive ? "Connection: close\r\n" : "");
        write_string(response, string_to_sv(response_body));

        write_all_bytes(response, compressed_echo);

    } else {
        response_body.len = snprintf(response_body.data, response_body.capacity, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n%s\r\n" SV_Fmt,
            (int)echo.len, request->keep_alive ? "Connection: close\r\n" : "", SV_Arg(echo));
        write_string(response, string_to_sv(response_body));
    }
}

void handle_route_files(Arena* arena, HttpRequest* request, HttpResponse* response)
{
    String response_body = { 0 };
    if (global_directory_path == NULL) {
        StringView response_404 = sv_from_cstr("HTTP/1.1 404 Not Found\r\n\r\n");
        response_body = sv_to_owned(arena, response_404);
    } else {

        StringView target_file = sv_from_cstr(hash_table_get(&request->route_params, SV_STATIC("file_path")));

        response_body = (String) {
            .data = arena_alloc(arena, KB(256)),
            .capacity = KB(256),
            .len = 0,
        };

        String file_path = (String) {
            .data = arena_alloc(arena, 256),
            .capacity = 256,
        };
        string_concat(&file_path, sv_from_cstr(global_directory_path));
        string_concat(&file_path, target_file); // assume file_path is null terminated because file_path is originally filled with zero bytes

        if (sv_eq(string_to_sv(request->method), SV_STATIC("GET"))) {
            String file = read_entire_file_arena(arena, file_path.data);
            if (file.len == 0) {
                if (request->keep_alive) {
                    StringView response_404 = sv_from_cstr("HTTP/1.1 404 Not Found\r\n\r\n");
                    response_body = sv_to_owned(arena, response_404);
                } else {
                    StringView response_404_closed = SV_STATIC("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
                    response_body = sv_to_owned(arena, response_404_closed);
                }
            } else {
                response_body.len = snprintf(response_body.data, response_body.capacity, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n%s\r\n" SV_Fmt,
                    (int)file.len, request->keep_alive ? "Connection: close\r\n" : "", SV_Arg(file));
            }
        } else if (sv_eq(string_to_sv(request->method), sv_from_cstr("POST"))) {
            StringView content_length_str = sv_from_cstr(hash_table_get(&request->headers, sv_from_cstr("content-length")));
            int content_length = sv_chop_u64(&content_length_str);
            StringView content = sv_from_parts(request->body.data, content_length);
            write_entire_file(file_path.data, content);

            if (request->keep_alive) {
                StringView response_201 = sv_from_cstr("HTTP/1.1 201 Created\r\n\r\n");
                response_body = sv_to_owned(arena, response_201);

            } else {
                StringView response_201_closed = SV_STATIC("HTTP/1.1 201 Created\r\nConnection: close\r\n\r\n");
                response_body = sv_to_owned(arena, response_201_closed);
            }
        } else {
            if (request->keep_alive) {
                StringView response_400 = sv_from_cstr("HTTP/1.1 400 Bad Request\r\n\r\n");
                response_body = sv_to_owned(arena, response_400);
            } else {
                StringView response_400_closed = SV_STATIC("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                response_body = sv_to_owned(arena, response_400_closed);
            }
        }
    }
    write_string(response, string_to_sv(response_body));
}

int compare_specificity(const void* a, const void* b)
{
    const RouteMapping* ra = (const RouteMapping*)a;
    const RouteMapping* rb = (const RouteMapping*)b;

    int sa = compute_specificity(ra->route);
    int sb = compute_specificity(rb->route);

    return sb - sa; // descending order
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

    RouteMapping route_mappings[] = {
        { .route = sv_from_cstr("/"), .handler = handle_route_index },
        { .route = sv_from_cstr("/echo/:echo"), .handler = handle_route_echo },
        { .route = sv_from_cstr("/files/:file_path"), .handler = handle_route_files },
        { .route = sv_from_cstr("/user-agent"), .handler = handle_route_user_agent },
    };

    qsort(route_mappings, ARRAY_COUNT(route_mappings), sizeof(RouteMapping), compare_specificity);

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

        Server* arg = malloc(sizeof(*arg)); // have to malloc it here so that it can be freed from the thread itself
        *arg = (Server) {
            .client_fd = client_fd,
            .mappings = (RouteMappings) {
                .data = route_mappings,
                .len = ARRAY_COUNT(route_mappings) },
            .default_404_handler = handle_route_404,
        };
        pool_add_task(pool, handle_socket_thread, arg);
    }

    // de-init
    close(server_fd);
    pool_destroy(pool);
    free(backing_buffer);
    return 0;
}
