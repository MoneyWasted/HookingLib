// EasyHook (File: EasyHookDll\alloc.c)
//
// Copyright (c) 2009 Christoph Husse & Copyright (c) 2015 Justin Stenning
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Please visit https://easyhook.github.io for more information
// about the project and latest updates.

#include "hooking_internal.h"

void* LhAllocateMemory(void* InEntryPoint)
{
    ULONG pageSize;
    return LhAllocateMemoryEx(InEntryPoint, &pageSize);
}

void* LhAllocateMemoryEx(void* InEntryPoint, ULONG* OutPageSize)
{
    if (OutPageSize == nullptr)
    {
        return nullptr;
    }

    SYSTEM_INFO info;
    GetSystemInfo(&info);

    const ULONG pageSize = info.dwPageSize;
    *OutPageSize = pageSize;

    const ULONG_PTR radius = 0x7FFFFF00;
    const ULONG_PTR entry = reinterpret_cast<ULONG_PTR>(InEntryPoint);
    const ULONG_PTR minimum = reinterpret_cast<ULONG_PTR>(info.lpMinimumApplicationAddress);
    const ULONG_PTR maximum = reinterpret_cast<ULONG_PTR>(info.lpMaximumApplicationAddress);
    const ULONG_PTR granularity = info.dwAllocationGranularity;

    if (entry < minimum || entry > maximum)
    {
        return nullptr;
    }

    const ULONG_PTR low = entry - minimum > radius ? entry - radius : minimum;
    const ULONG_PTR high = maximum - entry > radius ? entry + radius : maximum;

    ULONG_PTR below = entry - entry % granularity;
    ULONG_PTR above = below;

    bool haveBelow = below >= low;
    bool haveAbove = high - above >= granularity;

    if (haveAbove)
    {
        above += granularity;
    }

    while (haveBelow || haveAbove)
    {
        const bool searchBelow = haveBelow && (!haveAbove || entry - below <= above - entry);
        const ULONG_PTR candidate = searchBelow ? below : above;
        void* const address = reinterpret_cast<void*>(candidate);

        if (void* result = VirtualAlloc(address, pageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
        {
            return result;
        }

        MEMORY_BASIC_INFORMATION region = {};
        const bool occupied =
            VirtualQuery(address, &region, sizeof(region)) != 0 &&
            (region.State == MEM_RESERVE || region.State == MEM_COMMIT);

        if (searchBelow)
        {
            ULONG_PTR boundary = candidate;

            if (occupied)
            {
                // BaseAddress need not identify the start of the allocation.
                const ULONG_PTR allocationBase = reinterpret_cast<ULONG_PTR>(region.AllocationBase);
                if (allocationBase != 0 && allocationBase < boundary)
                {
                    boundary = allocationBase;
                }
            }

            // Find the aligned address strictly below boundary.
            if (boundary <= low)
            {
                haveBelow = false;
            }
            else
            {
                below = boundary - 1;
                below -= below % granularity;
                haveBelow = below >= low;
            }
        }
        else
        {
            if (occupied)
            {
                const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(region.BaseAddress);

                // Check before adding to avoid overflow.
                if (base > high || region.RegionSize > high - base)
                {
                    haveAbove = false;
                    continue;
                }

                const ULONG_PTR end = base + region.RegionSize;
                const ULONG_PTR remainder = end % granularity;
                const ULONG_PTR padding = remainder == 0 ? 0 : granularity - remainder;

                if (padding > high - end)
                {
                    haveAbove = false;
                }
                else
                {
                    above = end + padding;
                }
            }
            else
            {
                // Query failed, or allocation failed in apparently free memory.
                // Advance normally rather than skipping potentially usable space.
                if (high - above < granularity)
                {
                    haveAbove = false;
                }
                else
                {
                    above += granularity;
                }
            }
        }
    }

    return nullptr;
}