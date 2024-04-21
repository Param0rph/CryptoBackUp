#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <codecvt>

namespace fs = std::filesystem;

// Функция для шифрования данных
std::vector<unsigned char> EncryptData(const std::vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx;
    int len;
    std::vector<unsigned char> encryptedData(data.size() + AES_BLOCK_SIZE, 0);

    // Создание контекста шифрования
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cerr << "Failed to create cipher context." << std::endl;
        return std::vector<unsigned char>();
    }

    // Инициализация шифрования
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        std::cerr << "Failed to initialize encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    // Шифрование данных
    if (EVP_EncryptUpdate(ctx, &encryptedData[0], &len, data.data(), data.size()) != 1) {
        std::cerr << "Failed to encrypt data." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    int finalLen;
    // Завершение шифрования
    if (EVP_EncryptFinal_ex(ctx, &encryptedData[len], &finalLen) != 1) {
        std::cerr << "Failed to finalize encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>();
    }
    EVP_CIPHER_CTX_free(ctx);

    // Уменьшение размера вектора до фактического размера зашифрованных данных
    encryptedData.resize(len + finalLen);
    return encryptedData;
}

// Функция для дешифрования данных
std::vector<unsigned char> DecryptData(const std::vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx;
    int len;
    std::vector<unsigned char> decryptedData(data.size(), 0);

    // Создание контекста дешифрования
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cerr << "Failed to create cipher context." << std::endl;
        return std::vector<unsigned char>();
    }

    // Инициализация дешифрования
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        std::cerr << "Failed to initialize decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    // Дешифрование данных
    if (EVP_DecryptUpdate(ctx, &decryptedData[0], &len, data.data(), data.size()) != 1) {
        std::cerr << "Failed to decrypt data." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    int finalLen;
    // Завершение дешифрования
    if (EVP_DecryptFinal_ex(ctx, &decryptedData[len], &finalLen) != 1) {
        std::cerr << "Failed to finalize decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>();
    }
    EVP_CIPHER_CTX_free(ctx);

    // Уменьшение размера вектора до фактического размера расшифрованных данных
    decryptedData.resize(len + finalLen);
    return decryptedData;
}


// Функция для сжатия данных
std::vector<unsigned char> CompressData(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> compressedData;
    compressedData.resize(compressBound(data.size())); // Увеличиваем размер вектора для хранения сжатых данных
    uLongf compressedSize = compressedData.size();
    // Сжатие данных
    if (compress(&compressedData[0], &compressedSize, data.data(), data.size()) != Z_OK) {
        std::cerr << "Compression failed." << std::endl;
        return std::vector<unsigned char>(); // В случае ошибки возвращаем пустой вектор
    }
    // Уменьшение размера вектора до фактического размера сжатых данных
    compressedData.resize(compressedSize);
    return compressedData;
}

// Функция для распаковки данных
std::vector<unsigned char> DecompressData(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> decompressedData;
    decompressedData.resize(data.size() * 2); // Увеличиваем размер вектора для хранения распакованных данных
    uLongf decompressedSize = decompressedData.size();
    // Распаковка данных
    if (uncompress(&decompressedData[0], &decompressedSize, data.data(), data.size()) != Z_OK) {
        std::cerr << "Decompression failed." << std::endl;
        return std::vector<unsigned char>(); // В случае ошибки возвращаем пустой вектор
    }
    // Уменьшение размера вектора до фактического размера распакованных данных
    decompressedData.resize(decompressedSize);
    return decompressedData;
}


// Функция для выбора режима работы (шифрование/расшифровка)
bool ChooseMode() {
    char choice;
    std::cout << "Choose mode (e - encrypt, d - decrypt): ";
    std::cin >> choice;
    return (choice == 'e' || choice == 'E');
}

// Функция для ввода пути к директории
std::wstring GetDirectoryPathFromUser(const std::string& prompt) {
    std::string directoryPath;
    std::cout << prompt;
    std::cin >> directoryPath;
    return std::wstring(directoryPath.begin(), directoryPath.end());
}

// Функция для обработки файлов в указанной директории
void ProcessFilesInDirectory(const std::wstring& directoryPath, const std::wstring& outputDirectoryPath, const unsigned char* key, const unsigned char* iv, bool encrypt) {
    // Создаем выходную директорию, если она не существует
    if (!fs::exists(outputDirectoryPath))
        fs::create_directory(outputDirectoryPath);

    // Проходим по всем файлам в директории
    for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
        // Получаем путь к текущему файлу
        std::wstring filePath = entry.path();

        // Открываем файл для чтения в бинарном режиме
        std::ifstream inFile(filePath, std::ios::out | std::ios::binary);
        if (!inFile) {
            std::wcerr << "Failed to open file for reading: " << filePath << std::endl;
            continue;
        }

        // Считываем данные из файла
        std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        std::vector<unsigned char> returnedData;

        if (encrypt)
        {
            // Сжимаем данные
            std::vector<unsigned char> compressedData = CompressData(fileData);
            if (compressedData.empty()) {
                std::wcerr << "Compression failed for file: " << filePath << std::endl;
                continue;
            }
            fileData = compressedData;
            
            // Шифруем данные
            returnedData = EncryptData(compressedData, key, iv);

            if (returnedData.empty()) {
                std::wcerr << "Encryption failed for file: " << filePath << std::endl;
                continue;
            }
        }
        if (!encrypt)
        {
            // Расшифровываем данные
            std::vector<unsigned char> processedData;
            processedData = DecryptData(fileData, key, iv);
            if (processedData.empty()) {
                std::wcerr << "Decryption failed for file: " << filePath << std::endl;
                continue;
            }

            // Распаковываем данные
            std::vector<unsigned char> decompressedData = DecompressData(processedData);
            if (decompressedData.empty()) {
                std::wcerr << "Decompression failed for file: " << filePath << std::endl;
                continue;
            }
            returnedData = decompressedData;
        }

        // Получаем имя файла без пути
        std::wstring fileName = entry.path().filename().wstring();

        // Путь для сохранения обработанного файла
        std::wstring outputFilePath = outputDirectoryPath + L"\\" + fileName;

        // Записываем обработанные данные в файл
        std::ofstream outFile(outputFilePath, std::ios::out | std::ios::binary);
        if (!outFile) {
            std::wcerr << "Failed to create output file for writing: " << outputFilePath << std::endl;
            continue;
        }
        outFile.write(reinterpret_cast<const char*>(returnedData.data()), returnedData.size());
        outFile.close();

        std::wcout << (encrypt ? "Encryption" : "Decryption") << " completed for file: " << filePath << std::endl;
    }

    std::cout << (encrypt ? "Encryption" : "Decryption") << " process completed." << std::endl;
}

void generateKeyAndIV(const char* password, unsigned char* key, unsigned char* iv) {
    // Хеш пароля с помощью SHA256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password), strlen(password), hash);

    // Копируем первые 32 байта хеша в качестве ключа
    memcpy(key, hash, EVP_CIPHER_key_length(EVP_aes_256_cbc()));

    // Копируем первые 16 байт хеша в качестве IV
    memcpy(iv, hash, EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
}


int main() {
    while (true)
    {
        // Выбор режима работы
        bool encryptMode = ChooseMode();

        // Ввод пути к директории с файлами
        std::wstring directoryPath = GetDirectoryPathFromUser("Enter the directory path containing files: ");

        // Ввод пути к директории для сохранения обработанных файлов
        std::wstring outputDirectoryPath = GetDirectoryPathFromUser("Enter the directory path to save processed files: ");

        // Ключ и вектор инициализации для шифрования
        unsigned char key[AES_BLOCK_SIZE * 4]; // 32 байта
        unsigned char iv[AES_BLOCK_SIZE]; // 16 байт

        std::string password;
        std::cout << "Enter the password: ";
        std::cin >> password;

        const char* charPass = password.c_str();

        generateKeyAndIV(charPass, key, iv);

        // Обработка файлов в указанной директории
        ProcessFilesInDirectory(directoryPath, outputDirectoryPath, key, iv, encryptMode);
    }

    return 0;
}
