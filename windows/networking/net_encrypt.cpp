#include "net_encrypt.h"

const secure_string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(BYTE c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

__declspec(noinline)  secure_vector<unsigned char> net::net_base64_decode_ex(const  secure_string& encoded_string) {

    secure_vector<unsigned char> DecryptedBytes;

    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    BYTE char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                DecryptedBytes.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) DecryptedBytes.push_back(char_array_3[j]);
    }

    return DecryptedBytes;
}

__declspec(noinline) secure_string  net::net_base64_decode(const secure_string& encoded_string) {

    secure_vector<unsigned char> DcrVector = net_base64_decode_ex(encoded_string);

    if (DcrVector.empty())
        return secure_string();

    return secure_string(DcrVector.begin(), DcrVector.end());
}


__declspec(noinline) secure_vector<unsigned char> net::net_base64_encode_ex(const secure_string& encoded_string) {

    unsigned char const* bytes_to_encode = (unsigned char const*)encoded_string.data();
    unsigned int in_len = encoded_string.size();

    secure_vector<unsigned char> ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret.push_back(base64_chars[char_array_4[i]]);
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret.push_back(base64_chars[char_array_4[j]]);

        while ((i++ < 3))
            ret.push_back('=');

    }

    return ret;
}

__declspec(noinline) secure_string net::net_base64_encode(const secure_string& plain_string) {

    secure_vector<unsigned char> enc_vector = net_base64_encode_ex(plain_string);

    if (enc_vector.empty())
        return secure_string();

    return secure_string(enc_vector.begin(), enc_vector.end());
}

__declspec(noinline) secure_string net::binary_to_hex(secure_vector<unsigned char>& bin) {
    secure_string hex(bin.size() * 2 + 1, '\0');

    sodium_bin2hex(&hex[0], hex.size(), bin.data(), bin.size());

    hex.resize(strlen(hex.c_str()));
    return hex;
}

__declspec(noinline) secure_vector<unsigned char> net::hex_to_binary(const secure_string& hex) {

    secure_vector<unsigned char> bin(hex.size() / 2);
    size_t bin_len = 0;
    const char* hex_end = nullptr;

    int result = sodium_hex2bin(bin.data(), bin.size(),
        hex.c_str(), hex.size(),
        nullptr, &bin_len, &hex_end);

    if (result != 0) {
        bin.clear();
        return bin;
    }

    bin.resize(bin_len);
    return bin;
}

__declspec(noinline)  secure_string net::decrypt(secure_string data, encryption::encrypted_string encrypted_key, encryption::encrypted_string encrypted_iv)
{
    //  vm_high_start

   // dl_api::protection::watchdog::watchdog_data::check_watchdog();

    if (data.size() > 0) {

        // data = net_base64_decode(data);

        if (data.size() > 0) {

            auto key = hex_to_binary(encrypted_key.get_string());
            auto nonce = hex_to_binary(encrypted_iv.get_string());

            auto ciphertext = hex_to_binary(data);

            if (ciphertext.size() < crypto_secretbox_MACBYTES)
                return secure_string();

            secure_vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);

            if (crypto_secretbox_open_easy(decrypted.data(),
                reinterpret_cast<const unsigned char*>(ciphertext.data()),
                ciphertext.size(),
                reinterpret_cast<const unsigned char*>(nonce.data()),
                reinterpret_cast<const unsigned char*>(key.data())) == 0)
                return secure_string(decrypted.begin(), decrypted.end());
        }
    }
    //  vm_high_end
    return secure_string();
}

__declspec(noinline)  secure_string net::encrypt(secure_string data, encryption::encrypted_string encrypted_key, encryption::encrypted_string encrypted_iv)
{
    //vm_high_start

   // dl_api::protection::watchdog::watchdog_data::check_watchdog();

    if (data.size() > 0) {

        auto key = hex_to_binary(encrypted_key.get_string());
        auto nonce = hex_to_binary(encrypted_iv.get_string());

        secure_vector<unsigned char> ciphertext(data.size() + crypto_secretbox_MACBYTES);

        if (crypto_secretbox_easy(ciphertext.data(),
            reinterpret_cast<const unsigned char*>(data.data()),
            data.size(),
            reinterpret_cast<const unsigned char*>(nonce.data()),
            reinterpret_cast<const unsigned char*>(key.data())) == 0)
        {
            //  return net_base64_encode(binary_to_hex(ciphertext));
            return binary_to_hex(ciphertext);
        }
    }

    // vm_high_end

    return secure_string();
}