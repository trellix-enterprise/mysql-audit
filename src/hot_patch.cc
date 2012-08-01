#include "hot_patch.h"
#include "udis86.h"

#define UINT unsigned int
#define DWORD uint32_t
#define BYTE unsigned char
#ifdef __x86_64__
#define ULONG_PTR uint64_t
#else
#define ULONG_PTR uint32_t
#endif



#define unprotect(addr,len)  (mprotect(addr,len,PROT_READ|PROT_WRITE|PROT_EXEC))
#define protect(addr,len)  (mprotect(addr,len,PROT_READ|PROT_EXEC))
#define GETPAGESIZE()         sysconf (_SC_PAGE_SIZE)

static const unsigned long PAGE_SIZE = GETPAGESIZE() ;

//macro to log via sql_print_information only if cond test is enabled
#define cond_info_print(cond_test, ...) do{if(cond_test) sql_print_information(__VA_ARGS__);}while(0)


/*
 * Get the page address of a given pointer
 */
static DATATYPE_ADDRESS get_page_address(void * pointer)
{
	DATATYPE_ADDRESS pageMask = ( ~(PAGE_SIZE - 1) ) ;
	DATATYPE_ADDRESS longp = (unsigned long) pointer;
    return (longp & pageMask);
}

//
// This function  retrieves the necessary size for the jump
//

static UINT GetJumpSize(ULONG_PTR PosA, ULONG_PTR PosB)
{
#ifndef __x86_64__
    return 5;
#else
    return 14;
#endif
}

//
// This function writes unconditional jumps
// both for x86 and x64
//

static void WriteJump(void *pAddress, ULONG_PTR JumpTo)
{
    DWORD dwOldProtect = 0;
    DATATYPE_ADDRESS AddressPage = get_page_address(pAddress);
    unprotect((void*)AddressPage, PAGE_SIZE);

    BYTE *pCur = (BYTE *) pAddress;
#ifndef __x86_64__

	BYTE * pbJmpSrc = pCur + 5;
    *pCur++ = 0xE9;   // jmp +imm32
    *((ULONG_PTR *)pCur) = JumpTo - (ULONG_PTR)pbJmpSrc;    

#else

        *pCur = 0xff;       // jmp [rip+addr]
        *(++pCur) = 0x25;
        *((DWORD *) ++pCur) = 0; // addr = 0
        pCur += sizeof (DWORD);
        *((ULONG_PTR *)pCur) = JumpTo;

#endif
    //}

    DWORD dwBuf = 0;    // nessary othewrise the function fails

    protect((void*)AddressPage, PAGE_SIZE);
}

//
// Hooks a function
//
static bool  HookFunction(ULONG_PTR targetFunction, ULONG_PTR newFunction, ULONG_PTR trampolineFunction, unsigned int *trampolinesize)
{
    #define MAX_INSTRUCTIONS 100
    uint8_t raw[MAX_INSTRUCTIONS];
    unsigned int uCurrentSize =0;

#ifndef __x86_64__
    #define ASM_MODE 32
#else
    #define ASM_MODE 64
#endif
    memcpy (raw,(void*)targetFunction,MAX_INSTRUCTIONS);
    ud_t ud_obj;
    ud_init(&ud_obj);
    ud_set_input_buffer(&ud_obj, raw, MAX_INSTRUCTIONS);
    ud_set_mode(&ud_obj, ASM_MODE);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);


    DWORD InstrSize = 0;
    DATATYPE_ADDRESS trampolineFunctionPage = get_page_address((void*)trampolineFunction);
    unprotect((void*)trampolineFunctionPage, PAGE_SIZE);
    while (ud_disassemble(&ud_obj) && (strncmp (ud_insn_asm(&ud_obj),"invalid",7)!=0))
    {
        if (InstrSize >= GetJumpSize(targetFunction, newFunction))
            break;

        BYTE *pCurInstr = (BYTE *) (InstrSize + (ULONG_PTR) targetFunction);
        memcpy((BYTE*)trampolineFunction + uCurrentSize,
                (void *) pCurInstr, ud_insn_len (&ud_obj));

            uCurrentSize += ud_insn_len (&ud_obj);


        InstrSize += ud_insn_len (&ud_obj);
    }
    protect((void*)trampolineFunctionPage, PAGE_SIZE);
    WriteJump( (BYTE*)trampolineFunction + uCurrentSize, targetFunction + InstrSize);
    WriteJump((void *) targetFunction, newFunction);
    *trampolinesize = uCurrentSize;
    return true;
}

//
// Unhooks a function
//


static void UnhookFunction(ULONG_PTR Function,ULONG_PTR trampolineFunction , unsigned int trampolinesize)
{
    DATATYPE_ADDRESS FunctionPage = get_page_address((void*)Function);
    unprotect((void*)FunctionPage, PAGE_SIZE);
    memcpy((void *) Function, (void*)trampolineFunction,trampolinesize);
    protect((void*)FunctionPage, PAGE_SIZE);
}

/**
 * Hot patch a function.
 *
 * We are basically taking the code of the target function and putting at the start a jump to our new function.
 * Additionally we generate a trampoline function which the target function can call inorder to call the original function.
 *
 * trampolineFunction will be modified to contain the original code + jump code
 *
 * @param targetFunction the function to hot patch
 * @param newFunction the new function to be called instead of the targetFunction
 * @param trampolineFunction a function which will contain a jump back to the targetFunction. Function need to have
 * 			enough space of TRAMPOLINE_COPY_LENGTH + MIN_REQUIRED_FOR_DETOUR. Recommended to use a static function
 * 			which contains a bunch of nops. Use macro: TRAMPOLINE_NOP_DEF
 * @param log_file if not null will log about progress of installing the plugin
 * @Return 0 on success otherwise failure
 * @See MS Detours paper: http://research.microsoft.com/pubs/68568/huntusenixnt99.pdf for some background info.
 */
int hot_patch_function (void* targetFunction, void* newFunction, void * trampolineFunction, unsigned int *trampolinesize, bool info_print, const char * log_prefix)
{
	cond_info_print(info_print, "%s hot patching function: 0x%x", log_prefix, targetFunction);
    DATATYPE_ADDRESS trampolinePage = get_page_address(trampolineFunction);
    cond_info_print(info_print, "%s trampolineFunction: 0x%x trampolinePage: 0x%x",log_prefix, trampolineFunction, trampolinePage);
    if (HookFunction((ULONG_PTR) targetFunction, (ULONG_PTR) newFunction,
            (ULONG_PTR) trampolineFunction, trampolinesize))
    {
        return 0;
    }
    else
    {
        return -1;
    }    
}


/**
 * Restore a function back to its orginal state. Based uppon a trampoline function which
 * contains a copy of the original code.
 *
 * @param targetFunction the function to fix back
 * @param trampolineFunction a function which contains a jump back to the targetFunction.
 * @param log_file if not null will log about progress of installing the plugin
 */
void remove_hot_patch_function (void* targetFunction, void * trampolineFunction, unsigned int trampolinesize, bool info_print, const char * log_prefix)
{
	if(trampolinesize == 0)
	{
		//nothing todo. As hot patch was not set.
		return;
	}
	cond_info_print(info_print, "%s removing hot patching function: 0x%x",log_prefix, targetFunction);
	DATATYPE_ADDRESS targetPage = get_page_address(targetFunction);
	cond_info_print(info_print, "%s targetPage: 0x%x targetFunction: 0x%x",log_prefix, targetPage, targetFunction);

	UnhookFunction ((ULONG_PTR) targetFunction, (ULONG_PTR)trampolineFunction,trampolinesize);
	return;	
}
