#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

// Structure to hold response data
struct APIResponse {
    char *data;
    size_t size;
};

// Callback to write response data
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, struct APIResponse *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->data, response->size + realsize + 1);
    
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    
    return realsize;
}
// Initialize fuzzer
typedef struct {
    CURL *curl;
    char *base_url;
    char **wordlist;
    int wordlist_size;
    int delay_ms;
} Fuzzer;

Fuzzer* fuzzer_init(const char *url) {
    Fuzzer *fuzzer = malloc(sizeof(Fuzzer));
    if (!fuzzer) return NULL;
    
    fuzzer->curl = curl_easy_init();
    if (!fuzzer->curl) {
        free(fuzzer);
        return NULL;
    }
    
    fuzzer->base_url = strdup(url);
    fuzzer->wordlist = NULL;
    fuzzer->wordlist_size = 0;
    fuzzer->delay_ms = 100; // Default delay
    
    return fuzzer;
}

// Load wordlist from file
int load_wordlist(Fuzzer *fuzzer, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) return -1;
    
    char line[1024];
    int capacity = 1000;
    fuzzer->wordlist = malloc(capacity * sizeof(char*));
    
    while (fgets(line, sizeof(line), file) && fuzzer->wordlist_size < capacity) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0) {
            fuzzer->wordlist[fuzzer->wordlist_size] = strdup(line);
            fuzzer->wordlist_size++;
        }
    }
    
    fclose(file);
    return fuzzer->wordlist_size;
}

// Perform single request
int fuzz_request(Fuzzer *fuzzer, const char *path, struct APIResponse *response) {
    char *url = malloc(strlen(fuzzer->base_url) + strlen(path) + 2);
    sprintf(url, "%s/%s", fuzzer->base_url, path);
    
    // Reset response
    response->data = malloc(1);
    response->size = 0;
    
    // Configure curl
    curl_easy_setopt(fuzzer->curl, CURLOPT_URL, url);
    curl_easy_setopt(fuzzer->curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(fuzzer->curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(fuzzer->curl, CURLOPT_USERAGENT, "WebFuzzer/1.0");
    curl_easy_setopt(fuzzer->curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(fuzzer->curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    CURLcode res = curl_easy_perform(fuzzer->curl);
    long response_code;
    curl_easy_getinfo(fuzzer->curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    free(url);
    return (res == CURLE_OK) ? (int)response_code : -1;
}
// Run directory/file fuzzing
void run_directory_fuzz(Fuzzer *fuzzer) {
    printf("Starting directory fuzzing on %s\n", fuzzer->base_url);
    printf("Loaded %d words\n\n", fuzzer->wordlist_size);
    
    for (int i = 0; i < fuzzer->wordlist_size; i++) {
        struct APIResponse response = {0};
        int status = fuzz_request(fuzzer, fuzzer->wordlist[i], &response);
        
        if (status > 0) {
            printf("[%d] %s/%s", status, fuzzer->base_url, fuzzer->wordlist[i]);
            
            // Highlight interesting responses
            if (status == 200) {
                printf(" [FOUND]");
            } else if (status == 403) {
                printf(" [FORBIDDEN]");
            } else if (status == 301 || status == 302) {
                printf(" [REDIRECT]");
            }
            
            printf(" (Size: %zu)\n", response.size);
        }
        
        if (response.data) free(response.data);
        
        // Rate limiting
        usleep(fuzzer->delay_ms * 1000);
    }
}

// Parameter fuzzing
void run_parameter_fuzz(Fuzzer *fuzzer, const char *base_path) {
    printf("Starting parameter fuzzing on %s%s\n", fuzzer->base_url, base_path);
    
    for (int i = 0; i < fuzzer->wordlist_size; i++) {
        char path[2048];
        snprintf(path, sizeof(path), "%s?%s=test", base_path, fuzzer->wordlist[i]);
        
        struct APIResponse response = {0};
        int status = fuzz_request(fuzzer, path, &response);
        
        if (status > 0 && status != 404) {
            printf("[%d] %s Parameter: %s\n", status, fuzzer->base_url, fuzzer->wordlist[i]);
        }
        
        if (response.data) free(response.data);
        usleep(fuzzer->delay_ms * 1000);
    }
}
// Add custom headers
void set_custom_headers(Fuzzer *fuzzer) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "X-Forwarded-For: 127.0.0.1");
    headers = curl_slist_append(headers, "X-Real-IP: 127.0.0.1");
    curl_easy_setopt(fuzzer->curl, CURLOPT_HTTPHEADER, headers);
}

// POST data fuzzing
void run_post_fuzz(Fuzzer *fuzzer, const char *endpoint) {
    curl_easy_setopt(fuzzer->curl, CURLOPT_POST, 1L);
    
    for (int i = 0; i < fuzzer->wordlist_size; i++) {
        char post_data[1024];
        snprintf(post_data, sizeof(post_data), "%s=fuzzvalue", fuzzer->wordlist[i]);
        
        curl_easy_setopt(fuzzer->curl, CURLOPT_POSTFIELDS, post_data);
        
        struct APIResponse response = {0};
        int status = fuzz_request(fuzzer, endpoint, &response);
        
        if (status > 0 && status != 404) {
            printf("[%d] POST %s Data: %s\n", status, endpoint, post_data);
        }
        
        if (response.data) free(response.data);
        usleep(fuzzer->delay_ms * 1000);
    }
}

// Cleanup
void fuzzer_cleanup(Fuzzer *fuzzer) {
    if (fuzzer) {
        if (fuzzer->curl) curl_easy_cleanup(fuzzer->curl);
        if (fuzzer->base_url) free(fuzzer->base_url);
        
        for (int i = 0; i < fuzzer->wordlist_size; i++) {
            free(fuzzer->wordlist[i]);
        }
        free(fuzzer->wordlist);
        free(fuzzer);
    }
}
int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <url> <wordlist>\n", argv[0]);
        return 1;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    Fuzzer *fuzzer = fuzzer_init(argv[1]);
    if (!fuzzer) {
        printf("Failed to initialize fuzzer\n");
        return 1;
    }
    
    if (load_wordlist(fuzzer, argv[2]) < 0) {
        printf("Failed to load wordlist: %s\n", argv[2]);
        fuzzer_cleanup(fuzzer);
        return 1;
    }
    
    // Run different types of fuzzing
    run_directory_fuzz(fuzzer);
    run_parameter_fuzz(fuzzer, "");
    
    fuzzer_cleanup(fuzzer);
    curl_global_cleanup();
    
    return 0;
}
