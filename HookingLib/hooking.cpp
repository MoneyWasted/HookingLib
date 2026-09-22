#include "hooking.h"

#define NMD_LDISASM_IMPLEMENTATION
#include "nmd_ldisasm.h"

#include <Windows.h>
#include <Psapi.h>

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <algorithm>

#include "hooking_internal.h"

namespace
{
    constexpr size_t kLongJumpSize = 6 + sizeof(uint64_t); // FF 25 00000000 + abs64
    constexpr size_t kNearJumpSize = 5; // E9 rel32
    constexpr size_t kMaxInstrLength = 15;
    constexpr size_t kNotFound = SIZE_MAX;

    uintptr_t exeStart = 0;
    size_t exeLen = 0;

    uintptr_t trampolineRegion = 0;
    ULONG trampolineSize = 0;
    size_t trampolineCount = 0;

    HANDLE heap = nullptr;
}

bool EnsureExe()
{
    if (exeStart != 0)
    {
        return true;
    }

    MODULEINFO modInfo = {};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(nullptr), &modInfo, sizeof(modInfo)))
    {
        return false;
    }

    exeStart = (uintptr_t)modInfo.lpBaseOfDll;
    exeLen = (size_t)modInfo.SizeOfImage;
    return true;
}

bool EnsureHeap()
{
    if (heap == nullptr)
    {
        heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0x1000, 0x5000);
    }
    return heap != nullptr;
}

static inline bool memptn(const uint8_t* mem, const uint8_t* ptn, const uint8_t* mask, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if ((mem[i] ^ ptn[i]) & mask[i])
        {
            return false;
        }
    }
    return true;
}

static inline int HexNibble(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

// Single pass. Returns false (and leaves outputs null) on failure.
bool CompilePattern(const char* ptnStr, uint8_t** ptnBytes, uint8_t** maskBytes, size_t* ptnLen)
{
    *ptnBytes = nullptr;
    *maskBytes = nullptr;
    *ptnLen = 0;

    size_t strLen = strlen(ptnStr);
    size_t maxBytes = (strLen + 1) / 2; // upper bound; every char is at most one nibble

    uint8_t* pattern = (uint8_t*)calloc(maxBytes, 1);
    uint8_t* mask = (uint8_t*)calloc(maxBytes, 1);
    if (!pattern || !mask)
    {
        free(pattern);
        free(mask);
        return false;
    }

    size_t nibble = 0;
    for (size_t i = 0; i < strLen; i++)
    {
        char c = ptnStr[i];
        int v = HexNibble(c);
        int shift = (nibble & 1) ? 0 : 4;

        if (v >= 0)
        {
            mask[nibble / 2] |= 0xF << shift;
            pattern[nibble / 2] |= v << shift;
            nibble++;
        }
        else if (c == '.' || c == '*' || c == '?')
        {
            nibble++;
        }
    }

    *ptnBytes = pattern;
    *maskBytes = mask;
    *ptnLen = (nibble + 1) / 2;
    return true;
}

uintptr_t FindCompiledPattern(
    const uint8_t* pattern,
    const uint8_t* mask,
    size_t patternLength,
    const uint8_t* buffer,
    size_t bufferLength)
{
    if (patternLength == 0 || patternLength > bufferLength)
    {
        return kNotFound;
    }

    // Fast path: no wildcards -> plain memcmp, no mask work.
    bool fullMask = true;
    for (size_t i = 0; i < patternLength; i++)
    {
        if (mask[i] != 0xFF)
        {
            fullMask = false;
            break;
        }
    }

    // Boyer-Moore-Horspool skip table.
    size_t skip[256];
    std::fill(std::begin(skip), std::end(skip), patternLength);

    for (size_t i = 0; i + 1 < patternLength; i++)
    {
        size_t skipVal = patternLength - 1 - i;
        if (mask[i] == 0xFF)
        {
            skip[pattern[i]] = skipVal;
        }
        else
        {
            uint8_t m = mask[i], p = pattern[i] & m;
            for (int j = 0; j < 256; j++)
            {
                if ((j & m) == p)
                {
                    skip[j] = skipVal;
                }
            }
        }
    }

    const size_t last = patternLength - 1;
    const size_t end = bufferLength - patternLength;

    if (fullMask)
    {
        for (size_t idx = 0; idx <= end; idx += skip[buffer[idx + last]])
        {
            if (buffer[idx + last] == pattern[last] && memcmp(buffer + idx, pattern, last) == 0)
            {
                return idx;
            }
        }
    }
    else
    {
        for (size_t idx = 0; idx <= end; idx += skip[buffer[idx + last]])
        {
            if (memptn(buffer + idx, pattern, mask, patternLength))
            {
                return idx;
            }
        }
    }

    return kNotFound;
}

uintptr_t FindPatternEx(uintptr_t start, size_t len, const char* ptnStr, const int offset)
{
    uint8_t* pattern;
    uint8_t* mask;
    size_t patternLength;

    if (!CompilePattern(ptnStr, &pattern, &mask, &patternLength))
    {
        return 0;
    }

    uintptr_t rel = FindCompiledPattern(pattern, mask, patternLength, (const uint8_t*)start, len);

    free(pattern);
    free(mask);

    return rel == kNotFound ? 0 : rel + start - offset;
}

uintptr_t FindPatternEx(uintptr_t start, size_t len, const pattern& pattern)
{
    return FindPatternEx(start, len, pattern.pattern, pattern.offset);
}

uintptr_t FindPattern(const char* pattern, const int offset)
{
    return EnsureExe() ? FindPatternEx(exeStart, exeLen, pattern, offset) : 0;
}

uintptr_t FindPattern(const pattern& pattern)
{
    return FindPattern(pattern.pattern, pattern.offset);
}

uintptr_t GetExeBase(void)
{
    return EnsureExe() ? exeStart : 0;
}

bool WriteForeignMemory(uintptr_t target, const void* source, size_t length)
{
    DWORD oldProtect = 0;
    if (!VirtualProtect((void*)target, length, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return false;
    }

    memcpy((void*)target, source, length);

    DWORD dummy = 0;
    bool ok = VirtualProtect((void*)target, length, oldProtect, &dummy) != 0;
    FlushInstructionCache(GetCurrentProcess(), (void*)target, length);
    return ok;
}

uintptr_t NopInstruction(uintptr_t address)
{
    size_t length = nmd_x86_ldisasm((void*)address, NMD_LDISASM_X86_MODE_64);
    if (length == 0 || length > kMaxInstrLength)
    {
        return 0;
    }

    uint8_t nops[kMaxInstrLength];
    memset(nops, 0x90, length);

    return WriteForeignMemory(address, nops, length) ? address + length : 0;
}

bool WriteLongJump(uintptr_t from, uintptr_t target)
{
    uint8_t jmp[kLongJumpSize] = { 0xFF, 0x25, 0, 0, 0, 0 }; // jmp [rip+0]
    uint64_t t = (uint64_t)target;
    memcpy(jmp + 6, &t, sizeof(t));
    return WriteForeignMemory(from, jmp, sizeof(jmp));
}

// Shared logic for both hook flavours.
// Computes how many bytes the jump at branchAddress clobbers, and if that
// runs past returnAddress, copies the tail into an executable heap block
// followed by a long jump back. Returns the address to resume at, or 0.
//
// NOTE: copied instructions are NOT relocated. If the clobbered range contains
// RIP-relative or rel8/rel32 branches, the copy will be wrong.
static uintptr_t RelocatePrologue(uintptr_t branchAddress, uintptr_t returnAddress, size_t minHookLength)
{
    size_t skipLength = returnAddress - branchAddress;
    size_t clobberLength = 0;

    while (clobberLength < minHookLength)
    {
        size_t n = nmd_x86_ldisasm((void*)(branchAddress + clobberLength), NMD_LDISASM_X86_MODE_64);
        if (n == 0)
        {
            return 0;
        }
        clobberLength += n;
    }

    if (clobberLength <= skipLength)
    {
        return returnAddress;
    }

    size_t copyLength = clobberLength - skipLength;

    if (!EnsureHeap())
    {
        return 0;
    }

    // Always reserve room for the *long* jump back, regardless of hook type.
    uintptr_t stub = (uintptr_t)HeapAlloc(heap, 0, copyLength + kLongJumpSize);
    if (stub == 0)
    {
        return 0;
    }

    memcpy((void*)stub, (void*)returnAddress, copyLength);

    if (!WriteLongJump(stub + copyLength, returnAddress + copyLength))
    {
        HeapFree(heap, 0, (void*)stub);
        return 0;
    }

    return stub;
}

uintptr_t InsertHookWithSkip(uintptr_t branchAddress, uintptr_t returnAddress, uintptr_t hook)
{
    uintptr_t ret = RelocatePrologue(branchAddress, returnAddress, kLongJumpSize);
    if (ret == 0)
    {
        return 0;
    }

    return WriteLongJump(branchAddress, hook) ? ret : 0;
}

uintptr_t InsertHook(uintptr_t address, uintptr_t hook)
{
    return InsertHookWithSkip(address, address, hook);
}

bool InsertTrampoline(uintptr_t branchAddress, uintptr_t targetAddress)
{
    if (trampolineRegion == 0)
    {
        return false;
    }

    uintptr_t trampStart = trampolineRegion + trampolineCount * kLongJumpSize;

    if (trampStart + kLongJumpSize - trampolineRegion > trampolineSize)
    {
        return false;
    }

    // rel32 must be reachable from the branch site.
    intptr_t rel = (intptr_t)trampStart - (intptr_t)(branchAddress + kNearJumpSize);
    if (rel < INT32_MIN || rel > INT32_MAX)
    {
        return false;
    }

    if (!WriteLongJump(trampStart, targetAddress))
    {
        return false;
    }

    uint8_t jump[kNearJumpSize] = { 0xE9 };
    int32_t rel32 = (int32_t)rel;
    memcpy(jump + 1, &rel32, sizeof(rel32));

    if (!WriteForeignMemory(branchAddress, jump, sizeof(jump)))
    {
        return false;
    }

    trampolineCount++;
    return true;
}

uintptr_t InsertNearHookWithSkip(uintptr_t branchAddress, uintptr_t returnAddress, uintptr_t hook)
{
    uintptr_t ret = RelocatePrologue(branchAddress, returnAddress, kNearJumpSize);
    if (ret == 0)
    {
        return 0;
    }

    return InsertTrampoline(branchAddress, hook) ? ret : 0;
}

uintptr_t InsertNearHook(uintptr_t address, uintptr_t hook)
{
    return InsertNearHookWithSkip(address, address, hook);
}

bool InitializeNearHooks()
{
    if (!EnsureExe())
    {
        return false;
    }

    trampolineRegion = (uintptr_t)LhAllocateMemoryEx((void*)exeStart, &trampolineSize);
    if (trampolineRegion == 0)
    {
        return false;
    }

    DWORD oldProtect = 0;
    return VirtualProtect((void*)trampolineRegion, trampolineSize, PAGE_EXECUTE_READ, &oldProtect) != 0;
}

static uintptr_t DecodeRM(uintptr_t rmbyte)
{
    uint8_t rm = *(uint8_t*)rmbyte;

    // mod == 00, rm == 101 -> [rip + disp32]
    if ((rm >> 6) == 0 && (rm & 0x7) == 5)
    {
        return rmbyte + 5 + *(int32_t*)(rmbyte + 1);
    }

    return 0;
}

uintptr_t GetReferencedAddress(uintptr_t instruction)
{
    uint8_t opcode = *(uint8_t*)instruction;

    if ((opcode & 0xF0) == 0x40) // REX prefix
    {
        opcode = *(uint8_t*)(++instruction);
    }

    // rel32 / rel8 branches
    if (opcode == 0xE8 || opcode == 0xE9)
    {
        return instruction + 5 + *(int32_t*)(instruction + 1);
    }

    if ((opcode & 0xF0) == 0x70 || opcode == 0xEB)
    {
        return instruction + 2 + *(int8_t*)(instruction + 1);
    }

    if (opcode == 0x0F)
    {
        uint8_t op2 = *(uint8_t*)(++instruction);
        if ((op2 & 0xF0) == 0x80) // Jcc rel32
        {
            return instruction + 5 + *(int32_t*)(instruction + 1);
        }
        return 0;
    }

    // ModRM-based: add/mov/lea with RIP-relative operand
    if (opcode <= 0x03 || (opcode >= 0x88 && opcode <= 0x8B) || opcode == 0x8D)
    {
        return DecodeRM(instruction + 1);
    }

    return 0;
}

static inline bool isRttiLocator(size_t typeDescriptorFieldOffset)
{
    // Locator layout: [sig][offset][cdOffset][typeDescriptor][classHierarchy][self]
    // We're given the offset of the typeDescriptor field; self is at +0x8.
    if (typeDescriptorFieldOffset < 0xC || typeDescriptorFieldOffset + 0xC > exeLen)
    {
        return false;
    }

    uint32_t locatorOffset = (uint32_t)(typeDescriptorFieldOffset - 0xC);
    return *(uint32_t*)(exeStart + typeDescriptorFieldOffset + 0x8) == locatorOffset;
}

uintptr_t GetClassVftable(const char* className)
{
    if (!EnsureExe())
    {
        return 0;
    }

    const uint8_t* image = (const uint8_t*)exeStart;

    // 1. Locate the type descriptor name string.
    size_t nameLen = strlen(className) + 1;
    uint8_t* fullMask = (uint8_t*)malloc(nameLen);
    if (!fullMask)
    {
        return 0;
    }
    memset(fullMask, 0xFF, nameLen);

    uintptr_t stringOffset = FindCompiledPattern((const uint8_t*)className, fullMask, nameLen, image, exeLen);
    free(fullMask);

    if (stringOffset == kNotFound || stringOffset < 0x10)
    {
        return 0;
    }

    // 2. Find a CompleteObjectLocator referencing that TypeDescriptor (RVA).
    uint32_t typeInfoRva = (uint32_t)(stringOffset - 0x10);
    const uint8_t mask4[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    size_t cursor = 0;
    uintptr_t locatorField = kNotFound;

    while (cursor + 4 <= exeLen)
    {
        uintptr_t rel = FindCompiledPattern((const uint8_t*)&typeInfoRva, mask4, 4, image + cursor, exeLen - cursor);
        if (rel == kNotFound)
        {
            break;
        }

        size_t candidate = cursor + rel;
        if (isRttiLocator(candidate))
        {
            locatorField = candidate;
            break;
        }

        cursor = candidate + 1; // advance past a false positive
    }

    if (locatorField == kNotFound)
    {
        return 0;
    }

    // 3. Find the vftable: the pointer to the locator sits immediately before it.
    uint64_t locatorAddr = exeStart + (locatorField - 0xC);
    const uint8_t mask8[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    uintptr_t result = FindCompiledPattern((const uint8_t*)&locatorAddr, mask8, 8, image, exeLen);
    if (result == kNotFound)
    {
        return 0;
    }

    return exeStart + result + 8;
}