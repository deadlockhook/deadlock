#include "networking.h"
#include "../winapi/wrapper.h"

size_t write_callback(void* buffer, size_t size, size_t nmemb, void* param) {
    secure_string& text = *static_cast<secure_string*>(param);
    size_t totalsize = size * nmemb;
    text.append(static_cast<char*>(buffer), totalsize);
    return totalsize;
}

size_t write_callback_vector(char* data, size_t size, size_t nmemb, void* userdata) {
    size_t realSize = size * nmemb;
    secure_vector<char>* myVector = static_cast<secure_vector<char>*>(userdata);
    myVector->insert(myVector->end(), data, data + realSize);
    return realSize;
}

secure_string net::send_request(const secure_string& url) {

  //  vm_low_start

   //dl_api::protection::watchdog::watchdog_data::check_watchdog();

    secure_string result;

    CURLcode curlResult;
    CURL* pCurl = curl_easy_init();

    if (pCurl)
    {
        curl_easy_setopt(pCurl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &result);
        curl_easy_setopt(pCurl, CURLOPT_VERBOSE, 0L);
        curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, 0);
        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT_MS, 135000L);
        curlResult = curl_easy_perform(pCurl);
        curl_easy_cleanup(pCurl);
    }

   // vm_low_end

        return result;
}

secure_string net::send_request(const secure_string& szURL, const secure_string& post_fields) {

 //   vm_low_start

       // dl_api::protection::watchdog::watchdog_data::check_watchdog();

    secure_string result;

    CURLcode curlResult;
    CURL* pCurl = curl_easy_init();

    if (pCurl)
    {
        curl_easy_setopt(pCurl, CURLOPT_URL, szURL.c_str());
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, post_fields.c_str());
        curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &result);
        curl_easy_setopt(pCurl, CURLOPT_VERBOSE, 0L);
        curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, 0);
        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT_MS, 135000L);

        curlResult = curl_easy_perform(pCurl);

        curl_easy_cleanup(pCurl);
    }

    //vm_low_end

        return result;
}


__declspec(noinline) secure_string net::net_send_request_post(const secure_string& url, const secure_string& post_fields) {

   // vm_low_start

      //  dl_api::protection::watchdog::watchdog_data::check_watchdog();

    secure_string result;

    CURLcode curlResult;
    CURL* pCurl = curl_easy_init();

    if (pCurl)
    {
        curl_easy_setopt(pCurl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, post_fields.c_str());
        curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &result);
        curl_easy_setopt(pCurl, CURLOPT_VERBOSE, 0L);
        curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, 0);
        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT_MS, 135000L);

        curlResult = curl_easy_perform(pCurl);

        curl_easy_cleanup(pCurl);
    }
    //vm_low_end
    
    return result;
}

void net::net_download_file(secure_string FileUrl, secure_vector<_char>& BufferOut)
{
    CURL* curl;
    CURLcode res;
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, FileUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_vector);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &BufferOut);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            curl_easy_cleanup(curl);
            return;
        }

        curl_easy_cleanup(curl);
    }
}

_ulonglong_enc net::net_download_file_to_disk(secure_string url, secure_string path_on_disk)
{
    secure_vector<_char> Buffer;
    net_download_file(url, Buffer);

    unsigned long long bytes_written = 0;

    if (Buffer.size())
    {
        HANDLE file_handle = execute_call<HANDLE>(windows::api::kernel32::CreateFileA, (LPCSTR)path_on_disk.c_str(), GENERIC_WRITE, 0, (LPSECURITY_ATTRIBUTES)NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

        if (file_handle && file_handle != INVALID_HANDLE_VALUE)
        {
            DWORD dwBytesWritten = 0;
            execute_call<HANDLE>(windows::api::kernel32::WriteFile, file_handle, Buffer.data(), Buffer.size(), &dwBytesWritten, (LPOVERLAPPED)NULL);

            if (dwBytesWritten > 0)
                bytes_written = (_ulonglong)dwBytesWritten;

            execute_call(windows::api::kernel32::CloseHandle, file_handle);
        }

        _memset(Buffer.data(), 0, Buffer.size());
    }

    return bytes_written;
}