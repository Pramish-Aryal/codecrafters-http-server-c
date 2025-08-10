#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// LINUX SPECIFIC
#include <pthread.h>

////////////////////////////////////////
// prelude starts

#define ARRAY_COUNT(a) (sizeof(a) / sizeof(*(a)))

#define KB(x) (1024 * x)
#define MB(x) (KB(x) * 1024)
#define GB(x) (MB(x) * 1024)
#define TB(x) (GB(x) * 1024)

#define MIN(x, y) ((x) <= (y) ? (x) : (y))
#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define CLAMP_MAX(x, max) MIN(x, max)
#define CLAMP_MIN(x, min) MAX(x, min)

// taken from: https://www.gingerbill.org/article/2019/02/08/memory-allocation-strategies-002/
bool is_power_of_two(uintptr_t x)
{
    return (x & (x - 1)) == 0;
}

uintptr_t align_forward(uintptr_t ptr, size_t align)
{
    uintptr_t p, a, modulo;

    assert(is_power_of_two(align));

    p = ptr;
    a = (uintptr_t)align;
    // Same as (p % a) but faster as 'a' is a power of two
    modulo = p & (a - 1);

    if (modulo != 0) {
        // If 'p' address is not aligned, push the address to the
        // next value which is aligned
        p += a - modulo;
    }
    return p;
}

#ifndef DEFAULT_ALIGNMENT
#define DEFAULT_ALIGNMENT (2 * sizeof(void*))
#endif

typedef struct Arena Arena;
struct Arena {
    unsigned char* buf;
    size_t buf_len;
    size_t prev_offset;
    size_t curr_offset;
};

void arena_init(Arena* a, void* backing_buffer, size_t backing_buffer_length)
{
    a->buf = (unsigned char*)backing_buffer;
    a->buf_len = backing_buffer_length;
    a->curr_offset = 0;
    a->prev_offset = 0;
}

void* arena_alloc_align(Arena* a, size_t size, size_t align)
{
    // Align 'curr_offset' forward to the specified alignment
    uintptr_t curr_ptr = (uintptr_t)a->buf + (uintptr_t)a->curr_offset;
    uintptr_t offset = align_forward(curr_ptr, align);
    offset -= (uintptr_t)a->buf; // Change to relative offset

    // Check to see if the backing memory has space left
    if (offset + size <= a->buf_len) {
        void* ptr = &a->buf[offset];
        a->prev_offset = offset;
        a->curr_offset = offset + size;

        // Zero new memory by default
        memset(ptr, 0, size);
        return ptr;
    }
    // Return NULL if the arena is out of memory (or handle differently)
    return NULL;
}

// Because C doesn't have default parameters
void* arena_alloc(Arena* a, size_t size)
{
    return arena_alloc_align(a, size, DEFAULT_ALIGNMENT);
}

void arena_free(Arena* a, void* ptr)
{
    // Do nothing: LET IT LEAK
}

void* arena_resize_align(Arena* a, void* old_memory, size_t old_size, size_t new_size, size_t align)
{
    unsigned char* old_mem = (unsigned char*)old_memory;

    assert(is_power_of_two(align));

    if (old_mem == NULL || old_size == 0) {
        return arena_alloc_align(a, new_size, align);
    } else if (a->buf <= old_mem && old_mem < a->buf + a->buf_len) {
        if (a->buf + a->prev_offset == old_mem) {
            a->curr_offset = a->prev_offset + new_size;
            if (new_size > old_size) {
                // Zero the new memory by default
                memset(&a->buf[a->curr_offset], 0, new_size - old_size);
            }
            return old_memory;
        } else {
            void* new_memory = arena_alloc_align(a, new_size, align);
            size_t copy_size = old_size < new_size ? old_size : new_size;
            // Copy across old memory to the new memory
            memmove(new_memory, old_memory, copy_size);
            return new_memory;
        }

    } else {
        assert(0 && "Memory is out of bounds of the buffer in this arena");
        return NULL;
    }
}

// Because C doesn't have default parameters
void* arena_resize(Arena* a, void* old_memory, size_t old_size, size_t new_size)
{
    return arena_resize_align(a, old_memory, old_size, new_size, DEFAULT_ALIGNMENT);
}

void arena_free_all(Arena* a)
{
    a->curr_offset = 0;
    a->prev_offset = 0;
}

// Extra Features
typedef struct Temp_Arena_Memory Temp_Arena_Memory;
struct Temp_Arena_Memory {
    Arena* arena;
    size_t prev_offset;
    size_t curr_offset;
};

Temp_Arena_Memory temp_arena_memory_begin(Arena* a)
{
    Temp_Arena_Memory temp;
    temp.arena = a;
    temp.prev_offset = a->prev_offset;
    temp.curr_offset = a->curr_offset;
    return temp;
}

void temp_arena_memory_end(Temp_Arena_Memory temp)
{
    temp.arena->prev_offset = temp.prev_offset;
    temp.arena->curr_offset = temp.curr_offset;
}

// usage:
/*
unsigned char backing_buffer[256];
Arena a = {0};
arena_init(&a, backing_buffer, 256);

for (i = 0; i < 10; i++) {
        int *x;
        float *f;
        char *str;

        // Reset all arena offsets for each loop
        arena_free_all(&a);

        x = (int *)arena_alloc(&a, sizeof(int));
        f = (float *)arena_alloc(&a, sizeof(float));
        str = arena_alloc(&a, 10);

        *x = 123;
        *f = 987;
        memmove(str, "Hellope", 7);

        printf("%p: %d\n", x, *x);
        printf("%p: %f\n", f, *f);
        printf("%p: %s\n", str, str);

        str = arena_resize(&a, str, 10, 16);
        memmove(str+7, " world!", 7);
        printf("%p: %s\n", str, str);
}

arena_free_all(&a);
*/

// prelude ends
////////////////////////////////////////

////////////////////////////////////////
// types start

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct String {
    char* data;
    size_t len;
    size_t capacity;
} String;

typedef struct StringView {
    const char* data;
    size_t len;
} StringView;

typedef struct HashTableEntry {
    const char* key;
    void* value;
} HashTableEntry;

typedef struct HashTable {
    HashTableEntry* entries;
    Arena* arena;
    size_t capacity;
    size_t len;
} HashTable;

typedef struct TaskData {
    void* (*work_routine)(void*);
    void* arg;
} TaskData;

#define TASK_QUEUE_MAX 1000
typedef struct ThreadPool {
    pthread_t* worker_threads;
    TaskData* task_queue;
    int queue_head, queue_tail;
    int max_threads;
    int scheduled;
    Arena* arena;
    pthread_mutex_t mutex;
    pthread_cond_t work_available;
    pthread_cond_t done;
} ThreadPool;

struct TaskThreadArgs {
    ThreadPool* pool;
    TaskData data;
};

// types end
////////////////////////////////////////

////////////////////////////////////////
// function impl starts

#define internal static

internal bool
is_space(char c)
{
    return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}
internal bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/////////////////////////////////////////
// Vec impl start

#define VEC_INIT_CAP 16

#define vec_ensure_cap(arena, v, new_count)                                                                                 \
    do {                                                                                                                    \
        if ((new_count) >= (v)->capacity) {                                                                                 \
            size_t old_cap = (v)->capacity;                                                                                 \
            if ((v)->capacity == 0)                                                                                         \
                (v)->capacity = VEC_INIT_CAP;                                                                               \
            while ((v)->capacity <= (new_count))                                                                            \
                (v)->capacity *= 2;                                                                                         \
            (v)->data = arena_resize((arena), (v)->data, old_cap * sizeof(*(v)->data), (v)->capacity * sizeof(*(v)->data)); \
        }                                                                                                                   \
    } while (0)

#define vec_append(arena, v, item)              \
    do {                                        \
        vec_ensure_cap(arena, v, (v)->len + 1); \
        (v)->data[(v)->len++] = (item);         \
    } while (0)

#define vec_append_many(arena, v, addendum, addendum_count)                              \
    do {                                                                                 \
        vec_ensure_cap(arena, v, (v)->len + (addendum_count));                           \
        memcpy((v)->data + (v)->len, (addendum), (addendum_count) * sizeof(*(v)->data)); \
        (v)->len += (addendum_count);                                                    \
    } while (0)

// Vec impl end
////////////////////////////////////////

////////////////////////////////////////
// String and StringView impl start

// printf macros for StringView
#define SV_Fmt "%.*s"
#define SV_Arg(sv) (int)(sv).len, (sv).data

#define SV_NULL sv_from_parts(NULL, 0)

#define SV_STATIC(cstr_lit) \
    (StringView) { .len = sizeof(cstr_lit) - 1, .data = (cstr_lit) }

internal String
sv_to_owned(Arena* arena, StringView sv)
{
    String result = {};
    result.len = sv.len;
    result.capacity = sv.len;
    result.data = arena_alloc(arena, result.len + 1); // owned strings are always null terminated
    memcpy(result.data, sv.data, sv.len);
    result.data[result.len] = 0;
    return result;
}

internal StringView
string_to_sv(String s)
{
    StringView result = {
        .data = s.data,
        .len = s.len
    };
    return result;
}

internal void
string_to_lower(String s)
{
    for (int i = 0; i < s.len; ++i) {
        if (s.data[i] >= 'A' && s.data[i] <= 'Z') {
            s.data[i] ^= 32;
        }
    }
}

internal void
string_to_upper(String s)
{
    for (int i = 0; i < s.len; ++i) {
        if (s.data[i] >= 'a' && s.data[i] <= 'z') {
            s.data[i] ^= 32;
        }
    }
}

internal bool
string_concat(String* a, StringView b)
{
    if (a->capacity < a->len + b.len) {
        return false;
    }
    char* dest = a->data + a->len;
    for (int i = 0; i < b.len; ++i) {
        *dest++ = b.data[i];
    }
    a->len += b.len;
    return true;
}

internal StringView
sv_from_parts(const char* data, size_t len)
{
    StringView sv = {
        .data = data,
        .len = len,
    };
    return sv;
}

internal StringView
sv_from_cstr(const char* cstr)
{
    StringView sv = {
        .data = cstr,
        .len = strlen(cstr),
    };
    return sv;
}

internal StringView
sv_trim_left(StringView sv)
{
    int i = 0;
    while (i < sv.len && is_space(sv.data[i]))
        i++;
    sv.data += i;
    sv.len -= i;
    return sv;
}

internal StringView
sv_trim_right(StringView sv)
{
    int i = 0;
    while (i < sv.len && is_space(sv.data[sv.len - 1 - i]))
        i++;
    sv.len -= i;
    return sv;
}

internal StringView
sv_trim(StringView sv)
{
    return sv_trim_left(sv_trim_right(sv));
}

internal StringView
sv_chop_left(StringView* sv, size_t n)
{
    if (n > sv->len) {
        n = sv->len;
    }
    StringView result = sv_from_parts(sv->data, n);
    sv->data += n;
    sv->len -= n;
    return result;
}

internal StringView
sv_chop_right(StringView* sv, size_t n)
{
    if (n > sv->len) {
        n = sv->len;
    }
    StringView result = sv_from_parts(sv->data + sv->len - n, n);
    sv->len -= n;
    return result;
}

internal bool
sv_index_of(StringView sv, char c, size_t* index)
{
    int i = 0;
    while (i < sv.len && sv.data[i] != c)
        i++;
    if (i < sv.len) {
        if (index) {
            *index = i;
        }
        return true;
    } else {
        return false;
    }
}

internal bool
sv_eq(StringView a, StringView b)
{
    if (a.len != b.len)
        return false;
    return memcmp(a.data, b.data, a.len) == 0;
}

internal bool
sv_eq_string(String s, StringView sv)
{
    return sv_eq(string_to_sv(s), sv);
}

internal bool
sv_eq_ignorecase(StringView a, StringView b)
{
    if (a.len != b.len)
        return false;
    for (int i = 0; i < a.len; ++i) {
        if (a.data[i] != b.data[i] && a.data[i] != (b.data[i] ^ 32)) {
            return false;
        }
    }
    return true;
}

internal bool
sv_starts_with(StringView sv, StringView expected_prefix)
{
    if (expected_prefix.len <= sv.len) {
        StringView actual_prefix = sv_from_parts(sv.data, expected_prefix.len);
        return sv_eq(expected_prefix, actual_prefix);
    }
    return false;
}

internal bool
sv_ends_with(StringView sv, StringView expected_suffix)
{
    if (expected_suffix.len <= sv.len) {
        StringView actual_suffix = sv_from_parts(sv.data + sv.len - expected_suffix.len, expected_suffix.len);
        return sv_eq(expected_suffix, actual_suffix);
    }
    return false;
}

internal uint64_t
sv_to_u64(StringView sv)
{
    uint64_t result = 0;
    for (size_t i = 0; i < sv.len && is_digit(sv.data[i]); ++i) {
        result = result * 10 + (uint64_t)sv.data[i] - '0';
    }
    return result;
}

internal uint64_t
sv_chop_u64(StringView* sv)
{
    uint64_t result = 0;
    while (sv->len > 0 && is_digit(*sv->data)) {
        result = result * 10 + *sv->data - '0';
        sv->len -= 1;
        sv->data += 1;
    }
    return result;
}

internal StringView
sv_chop_by_delim(StringView* sv, char delim)
{
    int i = 0;
    while (i < sv->len && sv->data[i] != delim) {
        i++;
    }
    StringView result = sv_from_parts(sv->data, i);

    // sv->len -= i + (int)(i < sv->len);
    // sv->data += i + (int)(i < sv->len);
    if (i < sv->len) {
        sv->len -= i + 1;
        sv->data += i + 1;
    } else {
        sv->len -= i;
        sv->data += i;
    }
    return result;
}

internal StringView
sv_chop_by_sv(StringView* sv, StringView thicc_delim)
{
    StringView window = sv_from_parts(sv->data, thicc_delim.len);
    size_t i = 0;
    while (i + thicc_delim.len < sv->len
        && !(sv_eq(window, thicc_delim))) {
        i++;
        window.data++;
    }

    StringView result = sv_from_parts(sv->data, i);

    if (i + thicc_delim.len == sv->len) {
        // include last <thicc_delim.len> characters if they aren't equal to thicc_delim
        result.len += thicc_delim.len;
    }

    // Chop!
    sv->data += i + thicc_delim.len;
    sv->len -= i + thicc_delim.len;

    return result;
}

internal bool
sv_try_chop_by_delim(StringView* sv, char delim, StringView* chunk)
{
    size_t i = 0;
    while (i < sv->len && sv->data[i] != delim) {
        i += 1;
    }

    StringView result = sv_from_parts(sv->data, i);

    if (i < sv->len) {
        sv->len -= i + 1;
        sv->data += i + 1;
        if (chunk) {
            *chunk = result;
        }
        return true;
    }

    return false;
}

internal StringView
sv_chop_left_while(StringView* sv, bool (*predicate)(char x))
{
    size_t i = 0;
    while (i < sv->len && predicate(sv->data[i])) {
        i += 1;
    }
    return sv_chop_left(sv, i);
}

internal StringView
sv_take_left_while(StringView sv, bool (*predicate)(char x))
{
    size_t i = 0;
    while (i < sv.len && predicate(sv.data[i])) {
        i += 1;
    }
    return sv_from_parts(sv.data, i);
}

// String and StringView impl end
////////////////////////////////////////

////////////////////////////////////////
// Hashtable impl starts

#define TABLE_MAX_LOAD 0.75

void hash_table_init(Arena* arena, HashTable* table)
{
    table->capacity = 0;
    table->len = 0;
    table->entries = NULL;
    table->arena = arena;
}

void table_free(HashTable* table)
{
    arena_free(table->arena, table->entries);
    hash_table_init(table->arena, table);
}

static uint32_t hash_string(const char* key, int length)
{
    uint32_t hash = 2166136261u;
    for (int i = 0; i < length; i++) {
        hash ^= (uint8_t)key[i];
        hash *= 16777619;
    }
    return hash;
}

static HashTableEntry* find_entry_(HashTableEntry* entries, int capacity, StringView key)
{
    uint32_t index = hash_string(key.data, key.len) % capacity;
    HashTableEntry* tombstone = NULL;

    for (;;) {
        HashTableEntry* entry = &entries[index];
        if (entry->key == NULL) {
            if (entry->value == NULL) {
                return tombstone != NULL ? tombstone : entry;
            } else {
                if (tombstone == NULL)
                    tombstone = entry;
            }
        } else if (sv_eq(sv_from_cstr(entry->key), key)) {
            return entry;
        }

        index = (index + 1) % capacity;
    }
}

void* hash_table_get(HashTable* table, StringView key)
{
    if (table->len == 0)
        return NULL;

    HashTableEntry* entry = find_entry_(table->entries, table->capacity, key);
    if (entry->key == NULL)
        return NULL;

    return entry->value;
}

bool hash_table_delete(HashTable* table, StringView key)
{
    if (table->len == 0)
        return false;

    HashTableEntry* entry = find_entry_(table->entries, table->capacity, key);
    if (entry->key == NULL)
        return false;

    entry->key = NULL;
    entry->value = NULL;
    return true;
}

static void adjust_capacity(HashTable* table, int capacity)
{
    HashTableEntry* entries = arena_alloc(table->arena, sizeof(*entries) * capacity);

    for (int i = 0; i < capacity; ++i) {
        entries[i].key = NULL;
        entries[i].value = NULL;
    }

    table->len = 0;
    for (int i = 0; i < table->capacity; ++i) {
        HashTableEntry* entry = &table->entries[i];
        if (entry->key == NULL)
            continue;

        HashTableEntry* dest = find_entry_(entries, capacity, sv_from_cstr(entry->key));
        dest->key = entry->key;
        dest->value = entry->value;
        table->len++;
    }

    arena_free(table->arena, table->entries);
    table->entries = entries;
    table->capacity = capacity;
}

bool hash_table_set(HashTable* table, StringView key, void* value)
{
    if (table->len + 1 > table->capacity * TABLE_MAX_LOAD) {
        int capacity = table->capacity == 0 ? 8 : table->capacity * 2;
        adjust_capacity(table, capacity);
    }

    HashTableEntry* entry = find_entry_(table->entries, table->capacity, key);
    bool is_new_key = entry->key == NULL;
    if (is_new_key && entry->value == NULL)
        table->len++;

    entry->key = key.data;
    entry->value = value;
    return is_new_key;
}

// void table_add_all(HashTable* from, HashTable* to)
// {
//     for (int i = 0; i < from->capacity; i++) {
//         HashTableEntry* entry = &from->entries[i];
//         if (entry->key != NULL) {
//             tableSet(to, entry->key, entry->value);
//         }
//     }
// }

// Hashtable impl ends
////////////////////////////////////////

////////////////////////////////////////
// Threadpool impl starts

void* worker_thread_func(void* pool_arg)
{
    ThreadPool* pool = pool_arg;

    while (1) {
        TaskData picked_task;

        pthread_mutex_lock(&pool->mutex);

        while (pool->queue_head == pool->queue_tail) {
            pthread_cond_wait(&pool->work_available, &pool->mutex);
        }

        assert(pool->queue_head != pool->queue_tail);
        picked_task = pool->task_queue[pool->queue_head % TASK_QUEUE_MAX];
        pool->queue_head++;

        pool->scheduled++;

        pthread_mutex_unlock(&pool->mutex);

        picked_task.work_routine(picked_task.arg);

        pthread_mutex_lock(&pool->mutex);
        pool->scheduled--;

        if (pool->scheduled == 0) {
            pthread_cond_signal(&pool->done);
        }
        pthread_mutex_unlock(&pool->mutex);
    }
    return NULL;
}

void pool_add_task(ThreadPool* pool, void* (*work_routine)(void*), void* arg)
{
    pthread_mutex_lock(&pool->mutex);
    if (pool->queue_head == pool->queue_tail) {
        pthread_cond_broadcast(&pool->work_available);
    }

    TaskData task;
    task.work_routine = work_routine;
    task.arg = arg;

    pool->task_queue[pool->queue_tail % TASK_QUEUE_MAX] = task;
    pool->queue_tail++;

    pthread_mutex_unlock(&pool->mutex);
}

void pool_wait(ThreadPool* pool)
{
    pthread_mutex_lock(&pool->mutex);
    while (pool->scheduled > 0) {
        pthread_cond_wait(&pool->done, &pool->mutex);
    }
    pthread_mutex_unlock(&pool->mutex);
}

ThreadPool* pool_init(Arena* arena, int max_threads)
{
    ThreadPool* pool = arena_alloc(arena, sizeof(*pool));

    pool->arena = arena;
    pool->queue_head = pool->queue_tail = 0;
    pool->scheduled = 0;
    pool->task_queue = arena_alloc(arena, sizeof(*pool->task_queue) * TASK_QUEUE_MAX);

    pool->max_threads = max_threads;
    pool->worker_threads = arena_alloc(arena, sizeof(*pool->worker_threads) * max_threads);

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->work_available, NULL);
    pthread_cond_init(&pool->done, NULL);

    for (int i = 0; i < max_threads; i++) {
        pthread_create(&pool->worker_threads[i], NULL, worker_thread_func, pool);
    }

    return pool;
}

void pool_destroy(ThreadPool* pool)
{
    pool_wait(pool);
    for (int i = 0; i < pool->max_threads; i++) {
        pthread_detach(pool->worker_threads[i]);
    }
    arena_free(pool->arena, pool->worker_threads);
    arena_free(pool->arena, pool->task_queue);
    arena_free(pool->arena, pool);
}

// Threadpool impl ends
////////////////////////////////////////

// function impl ends
////////////////////////////////////////