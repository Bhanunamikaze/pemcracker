#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <chrono>
#include <cstring> 
#include <iomanip> 

// OpenSSL headers
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// --- Global Variables ---
std::queue<std::string> password_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;
std::atomic<bool> feeder_done(false);
std::atomic<bool> password_found(false);
std::atomic<uint64_t> attempts(0);
std::string found_password_value;
std::mutex result_mutex; // Protects found_password_value

// --- Password Callback for OpenSSL ---
// Called by OpenSSL's PEM_read_* functions to get the password.
// Copies the password from user data (`u`) into the OpenSSL buffer (`buf`).
int password_callback(char *buf, int size, int rwflag, void *u) {
    std::string* password_ptr = static_cast<std::string*>(u);
    if (password_ptr == nullptr || password_ptr->empty()) {
        return 0; // No password available
    }

    int len = static_cast<int>(password_ptr->length());

    // Ensure buffer overflow doesn't occur
    if (len >= size) {
        len = size - 1;
    }

    strncpy(buf, password_ptr->c_str(), len);
    buf[len] = '\0'; // Ensure null termination

    return len; // Return length of password copied
}

void worker_thread(int id, const std::vector<char>& pem_data) {
    while (true) {
        std::string current_password;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            // Wait until queue has data, or feeder is done, or password found
            queue_cv.wait(lock, [&]() {
                return !password_queue.empty() || feeder_done || password_found;
            });

            // Exit conditions
            if (password_found || (feeder_done && password_queue.empty())) {
                return;
            }
            if (password_found) return; // Check again after potential spurious wakeup

            current_password = password_queue.front();
            password_queue.pop();
        }

        attempts++;

        // --- Attempt Decryption ---
        // Create a memory BIO from the original PEM data for this attempt
        BIO* bio = BIO_new_mem_buf(pem_data.data(), static_cast<int>(pem_data.size()));
        if (!bio) {
            std::cerr << "Worker " << id << ": Failed to create memory BIO." << std::endl;
            ERR_print_errors_fp(stderr);
            continue;
        }

        // Attempt to read and decrypt the private key using the callback
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, password_callback, &current_password);
        BIO_free(bio);

        // --- Check Result ---
        if (pkey != NULL) {
            // Success!
            EVP_PKEY_free(pkey);
            // Atomically set flag and store password if this is the first thread to succeed
            if (!password_found.exchange(true)) {
                std::lock_guard<std::mutex> lock(result_mutex);
                found_password_value = current_password;
                std::cout << "\nWorker " << id << " found potential password!" << std::endl;
                queue_cv.notify_all(); // Notify others to stop
            }
            return; 
        } else {
            // Decryption failed - clear expected errors silently
            ERR_clear_error();
        }

        // Check if found by another thread after decryption attempt
        if (password_found) return;

    } 
}

// --- Main Function ---
int main(int argc, char* argv[]) {
    // --- Argument Parsing ---
    std::string pem_filepath;
    std::string wordlist_filepath;
    int num_workers = std::thread::hardware_concurrency();

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-pem" && i + 1 < argc) {
            pem_filepath = argv[++i];
        } else if (arg == "-wordlist" && i + 1 < argc) {
            wordlist_filepath = argv[++i];
        } else if (arg == "-workers" && i + 1 < argc) {
            try {
                num_workers = std::stoi(argv[++i]);
            } catch (const std::exception& e) {
                std::cerr << "Invalid number for workers: " << argv[i] << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Usage: " << argv[0] << " -pem <pem_file> -wordlist <wordlist_file> [-workers <num>]" << std::endl;
            return 1;
        }
    }

    if (pem_filepath.empty() || wordlist_filepath.empty()) {
        std::cerr << "Usage: " << argv[0] << " -pem <pem_file> -wordlist <wordlist_file> [-workers <num>]" << std::endl;
        return 1;
    }
    if (num_workers <= 0) {
        std::cerr << "Number of workers must be positive." << std::endl;
        num_workers = 1;
    }

    std::cout << "Starting PEM cracker with " << num_workers << " workers..." << std::endl;
    std::cout << "Target PEM file: " << pem_filepath << std::endl;
    std::cout << "Wordlist file: " << wordlist_filepath << std::endl;

    // --- Initialize OpenSSL ---
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // --- Read Encrypted PEM File ---
    std::ifstream pem_file(pem_filepath, std::ios::binary);
    if (!pem_file) {
        std::cerr << "Error opening PEM file: " << pem_filepath << std::endl;
        return 1;
    }
    std::vector<char> pem_data((std::istreambuf_iterator<char>(pem_file)),
                               std::istreambuf_iterator<char>());
    pem_file.close();

    if (pem_data.empty()) {
        std::cerr << "PEM file is empty: " << pem_filepath << std::endl;
        return 1;
    }
    // Optional: Check if file starts like a PEM file
    std::string pem_start_str(pem_data.begin(), pem_data.begin() + std::min<size_t>(pem_data.size(), 30));
    if (pem_start_str.find("-----BEGIN") == std::string::npos) {
         std::cerr << "Warning: File does not seem to start with '-----BEGIN'. Trying anyway." << std::endl;
    }

    // --- Start Timer ---
    auto start_time = std::chrono::high_resolution_clock::now();

    // --- Start Worker Threads ---
    std::vector<std::thread> workers;
    for (int i = 0; i < num_workers; ++i) {
        // Pass pem_data by const reference to avoid copying
        workers.emplace_back(worker_thread, i, std::cref(pem_data));
    }

    // --- Read Wordlist and Feed Queue (Password Feeder in Main Thread) ---
    std::ifstream wordlist_file(wordlist_filepath);
    if (!wordlist_file) {
        std::cerr << "Error opening wordlist file: " << wordlist_filepath << std::endl;
        feeder_done = true;
        queue_cv.notify_all();
        for (auto& t : workers) { if (t.joinable()) t.join(); }
        return 1;
    }

    std::string line;
    uint64_t lines_read = 0;
    std::cout << "Starting to read wordlist and distribute passwords..." << std::endl;
    while (std::getline(wordlist_file, line)) {
        if (password_found) {
            std::cout << "Password found, stopping wordlist reading." << std::endl;
            break;
        }
        // Optional: Cleanup line endings if necessary
        // if (!line.empty() && line.back() == '\r') line.pop_back();

        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            password_queue.push(line);
        }
        queue_cv.notify_one(); // Notify one waiting worker
        lines_read++;

        // Log progress periodically
         if (lines_read % 500000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
            double rate = (elapsed_ms.count() > 0) ? (static_cast<double>(attempts.load()) * 1000.0 / elapsed_ms.count()) : 0.0;
            std::cout << "Progress: Read " << lines_read << " lines. Attempts: " << attempts.load()
                      << " (Rate: " << std::fixed << std::setprecision(2) << rate << " attempts/sec)" << std::endl;
        }
    }
    wordlist_file.close();
    std::cout << "Finished reading wordlist or stopped early." << std::endl;

    // --- Signal Feeder Done ---
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        feeder_done = true;
    }
    queue_cv.notify_all(); // Notify any waiting workers feeder is done

    // --- Wait for Workers to Finish ---
    std::cout << "Waiting for workers to finish..." << std::endl;
    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }
    std::cout << "All workers finished." << std::endl;

    // --- Stop Timer and Calculate Stats ---
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    double duration_sec = duration_ms.count() / 1000.0;
    uint64_t final_attempts = attempts.load();
    double rate = (duration_sec > 0) ? (static_cast<double>(final_attempts) / duration_sec) : 0.0;

    // --- Print Final Result ---
    std::cout << "\nCracking process finished in " << std::fixed << std::setprecision(3) << duration_sec << " seconds." << std::endl;
    std::cout << "Total attempts: " << final_attempts << " (Average rate: " << std::fixed << std::setprecision(2) << rate << " attempts/sec)" << std::endl;

    if (password_found) {
        std::lock_guard<std::mutex> lock(result_mutex);
        std::cout << "\n>>> Success! Password found: " << found_password_value << std::endl;
    } else {
        std::cout << "\n>>> Password not found in the provided wordlist." << std::endl;
    }

    // --- Clean up OpenSSL ---
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
