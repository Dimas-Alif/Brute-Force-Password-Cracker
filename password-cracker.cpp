#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <chrono>
#include <atomic>
#include <openssl/evp.h>
#include <bcrypt.h> // Pastikan pustaka bcrypt telah terinstal
#include <random>

std::mutex foundMutex, logMutex, fileMutex;
std::atomic<bool> passwordFound(false);
std::atomic<size_t> combinationsTried(0);
std::chrono::steady_clock::time_point startTime;
std::string progressFile = "progress.txt";

// ==================== Fungsi Hashing ====================
std::string hashString(const std::string& str, const std::string& hashType, const std::string& salt = "") {
    std::string saltedStr = salt + str;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_get_digestbyname(hashType.c_str());

    if (!md) {
        std::cerr << "Algoritma hash tidak dikenal: " << hashType << "\n";
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, saltedStr.c_str(), saltedStr.size());
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);

    char outputBuffer[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < hashLen; ++i) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[hashLen * 2] = 0;

    return std::string(outputBuffer);
}

bool bcryptHashCheck(const std::string& password, const std::string& hashedPassword) {
    return bcrypt_checkpw(password.c_str(), hashedPassword.c_str()) == 0;
}

// ==================== Resume and Progress Management ====================
void saveProgress(size_t currentIndex) {
    std::lock_guard<std::mutex> lock(fileMutex);
    std::ofstream outFile(progressFile, std::ios::trunc);
    if (outFile.is_open()) {
        outFile << currentIndex << "\n";
        outFile.close();
    }
}

size_t loadProgress() {
    std::ifstream inFile(progressFile);
    size_t lastIndex = 0;
    if (inFile.is_open()) {
        inFile >> lastIndex;
        inFile.close();
    }
    return lastIndex;
}

// ==================== Dictionary Attack (Streaming) ====================
void dictionaryAttack(const std::string& targetHash, const std::string& dictionaryFile, const std::string& hashType, const std::string& salt, size_t startIndex, int numThreads) {
    std::ifstream file(dictionaryFile);
    if (!file.is_open()) {
        std::cerr << "Gagal membuka file dictionary.\n";
        return;
    }

    size_t currentIndex = 0;
    std::string word;
    while (std::getline(file, word)) {
        if (passwordFound) return;
        if (currentIndex++ < startIndex) continue;

        std::string hashedWord = hashString(word, hashType, salt);
        if (hashedWord == targetHash) {
            std::lock_guard<std::mutex> lock(foundMutex);
            if (!passwordFound) {
                passwordFound = true;
                std::cout << "\nPassword ditemukan dalam dictionary: " << word << "\n";
                saveProgress(currentIndex);
            }
            return;
        }

        saveProgress(currentIndex);
        combinationsTried++;
    }
}

// ==================== Brute Force ====================
void bruteForce(const std::string& targetHash, const std::string& characterSet, int maxLength, const std::string& hashType, const std::string& salt, size_t startIndex) {
    size_t totalCombinations = 0;
    for (int length = 1; length <= maxLength; ++length) {
        totalCombinations += std::pow(characterSet.size(), length);
    }

    size_t currentIndex = startIndex;
    while (currentIndex < totalCombinations && !passwordFound) {
        std::string attempt;
        size_t index = currentIndex++;
        for (int i = 0; i < maxLength; ++i) {
            attempt.insert(attempt.begin(), characterSet[index % characterSet.size()]);
            index /= characterSet.size();
        }

        if (hashString(attempt, hashType, salt) == targetHash) {
            std::lock_guard<std::mutex> lock(foundMutex);
            if (!passwordFound) {
                passwordFound = true;
                std::cout << "\nPassword ditemukan melalui brute force: " << attempt << "\n";
                saveProgress(currentIndex);
            }
            return;
        }

        saveProgress(currentIndex);
        combinationsTried++;
    }
}

// ==================== Fungsi Utama ====================
int main() {
    // Target password
    std::string targetPassword = "Ab#1";
    std::string hashType = "sha256"; // Bisa diganti dengan "bcrypt" untuk bcrypt hashing
    std::string salt = "123";       // Salt opsional
    std::string targetHash;

    if (hashType == "bcrypt") {
        targetHash = bcrypt_hashpw(targetPassword.c_str(), bcrypt_gensalt());
    } else {
        targetHash = hashString(targetPassword, hashType, salt);
    }

    std::string characterSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    int maxLength = 5;

    std::string dictionaryFile = "dictionary.txt";
    size_t startIndex = loadProgress();

    startTime = std::chrono::steady_clock::now();

    std::cout << "Mencoba memecahkan password menggunakan " << hashType << " hashing.\n";
    std::cout << "Password target (hash): " << targetHash << "\n";

    std::thread dictionaryThread(dictionaryAttack, targetHash, dictionaryFile, hashType, salt, startIndex, 1);
    dictionaryThread.join();

    if (!passwordFound) {
        std::cout << "Memulai brute force attack...\n";
        bruteForce(targetHash, characterSet, maxLength, hashType, salt, startIndex);
    }

    auto endTime = std::chrono::steady_clock::now();
    double elapsedTime = std::chrono::duration<double>(endTime - startTime).count();

    if (!passwordFound) {
        std::cout << "\nPassword tidak ditemukan dalam waktu maksimum atau panjang kombinasi yang diberikan.\n";
    }
    std::cout << "Total waktu eksekusi: " << elapsedTime << " detik.\n";
    std::cout << "Total kombinasi yang dicoba: " << combinationsTried.load() << "\n";

    return 0;
}
