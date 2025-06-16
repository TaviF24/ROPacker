#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>
#include <math.h>
#include <imagehlp.h>
#include "zlib.h"
#include <cstdint>
#include <random>

using namespace std;

#define STUB_FILE "stub.exe"

bool is64bitArchitecture() {
    SYSTEM_INFO sysInfo = {};
    GetNativeSystemInfo(&sysInfo);

    if(sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64){
        return true;
    }
    printf("[FAIL] Architecture not compatible\n");
    return false;
}

bool compress(BYTE* input, uInt inputSize, BYTE* output, uInt* outputSize){
    z_stream stream = {0};
    stream.next_in = input;
    stream.avail_in = inputSize;
    stream.next_out = output;
    stream.avail_out = *outputSize;
    int returnValue = deflateInit(&stream, Z_BEST_COMPRESSION);
    if(returnValue != Z_OK){
        printf("[FAIL] Initiate compress function\n");
        return false;
    }

    returnValue = deflate(&stream, Z_FINISH);
    if(returnValue != Z_STREAM_END){
        printf("[FAIL] Compress function executed\n");
        return false;
    }
    deflateEnd(&stream);
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

bool generateKey(uint32_t key[4]) {

    uint32_t salt[4];
    random_device randomDevice;
    mt19937 gen(randomDevice());
    uniform_int_distribution<uint32_t> uniformDistribution;

    for (int i = 0; i < 4; i++) {
        salt[i] = uniformDistribution(gen);
    }

    time_t timestamp = time(nullptr);

    unsigned char buffer[sizeof(timestamp) + sizeof(salt)];
    memcpy(buffer, &timestamp, sizeof(timestamp));
    memcpy(buffer + sizeof(timestamp), salt, sizeof(salt));

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32]; // sha-256 is 32 bytes
    DWORD hashLen = 32;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, buffer, sizeof(buffer), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    for (int i = 0; i < 4; ++i) {
        key[i] = ((uint32_t) hash[i * 4] << 24) |
                 ((uint32_t) hash[i * 4 + 1] << 16) |
                 ((uint32_t) hash[i * 4 + 2] << 8) |
                 ((uint32_t) hash[i * 4 + 3]);
    }

    return true;
}

void encrypt(uint32_t* plaintextBlock, uint32_t* key, uint32_t delta) {
    uint32_t half0 = plaintextBlock[0], half1 = plaintextBlock[1], sum = 0, numberOfRounds = 32;
    for (uint32_t i = 0; i < numberOfRounds; ++i) {
        half0 += (((half1 << 4) ^ (half1 >> 5)) + half1) ^ (sum + key[sum & 3]);
        sum += delta;
        half1 += (((half0 << 4) ^ (half0 >> 5)) + half0) ^ (sum + key[(sum >> 11) & 3]);
    }
    plaintextBlock[0] = half0; 
    plaintextBlock[1] = half1;
}

BYTE* encryptAll(BYTE* data, size_t size, uint32_t* key, size_t& outSize) {
    size_t paddedSize = int(ceil(double(size + 4) / 8.0))*8; // size must be a multiple of 8 => padding if needed
    
    BYTE* encrypted = (BYTE*)malloc(paddedSize);
    if(encrypted == NULL){
        printf("[FAIL] Allocate memory for encrypted file\n");
        return NULL;
    }

    memset(encrypted, 0, paddedSize);

    // store original size at start
    *(uint32_t*)encrypted = (uint32_t)size;
    memcpy(encrypted + 4, data, size);
    uint32_t delta = generateDelta();

    for (size_t i = 0; i < paddedSize; i += 8) {
        encrypt((uint32_t*)(encrypted + i), key, delta);
    }

    outSize = paddedSize;
    return encrypted;
}

bool recalculateCheckSum(const char* fileName){
    DWORD *oldCheckSum = (DWORD *) malloc(sizeof(DWORD));
    if(oldCheckSum == NULL){
        printf("[FAIL] Allocate memory for old checksum\n");
        return false;
    }
    DWORD *newCheckSum = (DWORD *) malloc(sizeof(DWORD));
    if(newCheckSum == NULL){
        printf("[FAIL] Allocate memory for new checksum\n");
        return false;
    }
    if(MapFileAndCheckSumA(fileName, oldCheckSum, newCheckSum) != CHECKSUM_SUCCESS){
        printf("[FAIL] Calculate the checksum for new file\n");
        return false;
    }
    
    FILE *outputFile = fopen(fileName, "rb+");
    if(outputFile == NULL){
        printf("[FAIL] Open output file\n");
        return false;
    }

    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, outputFile);
    if(ferror(outputFile)){
        printf("[FAIL] Read output file for calculating checksum - DOS Header\n");
        return false;
    }

    long fileHeaderOffset = dosHeader.e_lfanew;
    fseek(outputFile, fileHeaderOffset, SEEK_SET);
    IMAGE_NT_HEADERS fileHeader;
    fread(&fileHeader, sizeof(IMAGE_NT_HEADERS), 1, outputFile);
    if(ferror(outputFile)){
        printf("[FAIL] Read output file for calculating checksum - NT Headers\n");
        return false;
    }

    fseek(outputFile, fileHeaderOffset, SEEK_SET);
    fileHeader.OptionalHeader.CheckSum = *newCheckSum;
    size_t returnValue = fwrite(&fileHeader, sizeof(IMAGE_NT_HEADERS), 1, outputFile);
    if(returnValue < 1){
        printf("[FAIL] Write new checksum to output file - NT Headers\n");
        return false;
    }

    fclose(outputFile);
    free(oldCheckSum);
    free(newCheckSum);

    return true;
}

long getSizeOfFile(FILE* file){
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

bool addSection(const char* sectionName, const char* inputFileName, const char* outputFileName){

    FILE* stubFile = fopen("stub.exe", "rb");
    if(stubFile == NULL){
        printf("[FAIL] Open stub file\n");
        return false;
    }

    FILE* inputFile = fopen(inputFileName, "rb"); 
    if(inputFile == NULL){
        printf("[FAIL] Open input file\n");
        return false;
    }

    FILE *outputFile = fopen(outputFileName, "wb");
    if(outputFile == NULL){
        printf("[FAIL] Create output file\n");
        return false;
    }

    long stubSize = getSizeOfFile(stubFile);
    if(stubSize == -1){
        printf("[FAIL] Get size of stub file\n");
        return false;
    }

    long inputSizeTemp = getSizeOfFile(inputFile);
    if(inputSizeTemp == -1){
        printf("[FAIL] Get size of input file\n");
        return false;
    }
    DWORD inputSize = getSizeOfFile(inputFile);

    uint32_t key[4];
    if(!generateKey(key)){
        return false;
    }
    uint32_t paddingForOutput = sizeof(DWORD) + 4 * sizeof(uint32_t); //original size + 128 bit key
    // uint32_t paddingForOutput = sizeof(DWORD) + sizeof(uint32_t); //original size + 128 bit key

    BYTE* buf2 = (BYTE*)malloc(inputSize);
    if(buf2 == NULL){
        printf("[FAIL] Allocate memory for input file\n");
        return false;
    }
    memset(buf2, 0, inputSize);
    fread(buf2, 1, inputSize, inputFile);
    if(ferror(inputFile)){
        printf("[FAIL] Read input file\n");
        return false;
    }

    BYTE* compressedInputFile = (BYTE*)malloc(inputSize);
    if(compressedInputFile == NULL){
        printf("[FAIL] Allocate memory for compressed input file\n");
        return false;
    }

    UINT *compressedFileSize = (UINT*)malloc(sizeof(uInt));
    if(compressedFileSize == NULL){
        printf("[FAIL] Allocate memory for compressed file size\n");
        return false;
    }

    if(compress(buf2, inputSize, compressedInputFile, compressedFileSize)){
        printf("[SUCCESS] Compression for input file\n");
    }else{
        return false;
    }
    
    size_t encryptedFileSize = 0;
    BYTE* encryptedInputFile = encryptAll(compressedInputFile, *compressedFileSize, key, encryptedFileSize);
    if(encryptedInputFile != NULL){
        printf("[SUCCESS] Encryption for input file\n");
    }

    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, stubFile);
    if(ferror(stubFile)){
        printf("[FAIL] Read stub file - DOS Header\n");
        return false;
    }

    long fileHeaderOffset = dosHeader.e_lfanew;
    fseek(stubFile, 0, SEEK_SET);
    BYTE* dosHeaderStub = (BYTE*)malloc(fileHeaderOffset);
    if(dosHeaderStub == NULL){
        printf("[FAIL] Allocate memory for DOS Header stub\n");
        return false;
    }

    fread(dosHeaderStub, fileHeaderOffset, 1, stubFile);
    if(ferror(stubFile)){
        printf("[FAIL] Read stub file - DOS Header stub\n");
        return false;
    }
    
    size_t returnValue = fwrite(dosHeaderStub, fileHeaderOffset, 1, outputFile);
    if(returnValue < 1){
        printf("[FAIL] Write stub file - DOS Header stub\n");
        return false;
    }

    free(dosHeaderStub);
    IMAGE_NT_HEADERS fileHeader;
    fread(&fileHeader, sizeof(IMAGE_NT_HEADERS), 1, stubFile);
    if(ferror(stubFile)){
        printf("[FAIL] Read stub file - NT Headers\n");
        return false;
    }
    if(fileHeader.Signature != IMAGE_NT_SIGNATURE){
        printf("[FAIL] Signature match\n");
        return false;
    }

    int nrOfSections = ++fileHeader.FileHeader.NumberOfSections;
    fileHeader.OptionalHeader.SizeOfImage += (int(ceil(double(encryptedFileSize + paddingForOutput) / double(fileHeader.OptionalHeader.SectionAlignment))))  *  fileHeader.OptionalHeader.SectionAlignment; //encryptedFileSize + paddingForOutput;
    // fileHeader.OptionalHeader.SizeOfImage += encryptedFileSize + paddingForOutput;
    returnValue = fwrite(&fileHeader, sizeof(IMAGE_NT_HEADERS), 1, outputFile);
    if(returnValue < 1){
        printf("[FAIL] Write stub file - old NT Headers\n");
        return false;
    }
    
    IMAGE_SECTION_HEADER *sectionTableHeader = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER)*nrOfSections);
    if(sectionTableHeader == NULL){
        printf("[FAIL] Allocate memory for Section Headers\n");
        return false;
    }

    fread(sectionTableHeader, sizeof(IMAGE_SECTION_HEADER), nrOfSections-1, stubFile); 
    if(ferror(stubFile)){
        printf("[FAIL] Read stub file - Old Section Headers\n");
        return false;
    }

    int lastSection = nrOfSections-1;
    memset(sectionTableHeader[lastSection].Name, 0, sizeof(sectionTableHeader[lastSection].Name));
    mempcpy(sectionTableHeader[lastSection].Name, sectionName, strlen(sectionName));
    sectionTableHeader[lastSection].PointerToRawData = sectionTableHeader[lastSection-1].PointerToRawData + sectionTableHeader[lastSection-1].SizeOfRawData;
    // DWORD sizeRawData = (long(ceil(double(encryptedFileSize + paddingForOutput)/double(fileHeader.OptionalHeader.FileAlignment))) + 1) * fileHeader.OptionalHeader.FileAlignment;
    sectionTableHeader[lastSection].SizeOfRawData = encryptedFileSize + paddingForOutput;
    sectionTableHeader[lastSection].Misc.VirtualSize = encryptedFileSize + paddingForOutput;
    sectionTableHeader[lastSection].NumberOfLinenumbers = 0;
    sectionTableHeader[lastSection].NumberOfRelocations = 0;
    sectionTableHeader[lastSection].PointerToRelocations = 0;
    sectionTableHeader[lastSection].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    sectionTableHeader[lastSection].PointerToLinenumbers = 0;
    long lastSectionVSize = sectionTableHeader[lastSection-1].Misc.VirtualSize;
    long lastSectionVAdd = sectionTableHeader[lastSection-1].VirtualAddress;
    long secAlign = fileHeader.OptionalHeader.SectionAlignment;
    sectionTableHeader[lastSection].VirtualAddress = (int(ceil((lastSectionVAdd + lastSectionVSize) / (secAlign))) + 1)  *  secAlign; 

    returnValue = fwrite(sectionTableHeader, sizeof(IMAGE_SECTION_HEADER), fileHeader.FileHeader.NumberOfSections, outputFile);
    if(returnValue < fileHeader.FileHeader.NumberOfSections){
        printf("[FAIL] Write stub file - last Section Header\n");
        return false;
    }

    fseek(stubFile, sizeof(IMAGE_SECTION_HEADER), SEEK_CUR);
    int remainingBytes = stubSize - ftell(stubFile);
    BYTE* buf = (BYTE*)malloc(remainingBytes);
    if(buf == NULL){
        printf("[FAIL] Allocate memory for Sections\n");
        return false;
    }
    fread(buf, 1, remainingBytes, stubFile);
    if(ferror(stubFile)){
        printf("[FAIL] Read stub file - Sections\n");
        return false;
    }
    returnValue = fwrite(buf, remainingBytes,  1, outputFile);
    if(returnValue < 1){
        printf("[FAIL] Write stub file - Sections\n");
        return false;
    }
    
    fwrite(encryptedInputFile, paddingForOutput,  1, outputFile); // 8 = sizeof(DWORD) + sizeof(key[0])
    fwrite(key, sizeof(key[0]), 1, outputFile);
    fwrite(&inputSize, sizeof(inputSize), 1, outputFile);

    size_t middleKeyOffset = (encryptedFileSize - paddingForOutput) / 3;
    
    fwrite(encryptedInputFile + paddingForOutput, middleKeyOffset,  1, outputFile);
    fwrite(key+1, sizeof(key[0]), 1, outputFile);
    fwrite(encryptedInputFile + paddingForOutput + middleKeyOffset, middleKeyOffset,  1, outputFile);
    fwrite(key+2, sizeof(key[0]), 1, outputFile);
    
    size_t restOfFile = encryptedFileSize - paddingForOutput - 2*middleKeyOffset ;//- 2*sizeof(key[0]);

    fwrite(encryptedInputFile + paddingForOutput + 2*middleKeyOffset, restOfFile,  1, outputFile);
    returnValue = fwrite(key+3, sizeof(key[0]), 1, outputFile);


    /*
    // fwrite(encryptedInputFile, paddingForOutput,  1, outputFile);
    // fwrite(key, sizeof(key[0]), 1, outputFile);
    // fwrite(&inputSize, sizeof(inputSize), 1, outputFile);
    // fwrite(key+1, sizeof(key[0]) * 3, 1, outputFile);
    // // fwrite(key, sizeof(key), 1, outputFile);
    // returnValue = fwrite(encryptedInputFile + paddingForOutput, encryptedFileSize - paddingForOutput,  1, outputFile);
    */
    if(returnValue < 1){
        printf("[FAIL] Write stub file - new section\n");
        return false;
    }
// ab8c raw size
    free(buf);
    free(buf2);
    free(sectionTableHeader);
    free(encryptedInputFile);
    free(compressedInputFile);
    free(compressedFileSize);
    fclose(stubFile);
    fclose(inputFile);
    fclose(outputFile);

    return true;
}

int main(int argc, char* argv[]){
    if(argc < 3){
        printf("[FAIL] Incorrect number of parameters. Correct form: packer.exe <inputFile.exe> <outputFile.exe>");
        return 0;
    }
    if(is64bitArchitecture() && addSection(".debug", argv[1], argv[2]) && recalculateCheckSum(argv[2])){
        printf("[SUCCESS] Created new packed file\n");
    }else{
        printf("[FAIL] Created new packed file\n");
    }
    return 0;
}