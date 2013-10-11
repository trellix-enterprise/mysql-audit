#include "hot_patch.h"
#include "udis86.h"
#include <ctype.h>

#define UINT unsigned int
#define DWORD uint32_t
#define BYTE unsigned char
#ifdef __x86_64__
#define ULONG_PTR uint64_t
#else
#define ULONG_PTR uint32_t
#endif

static const char * log_prefix = "Audit Plugin:";

static const unsigned long PAGE_SIZE = GETPAGESIZE() ;

//used to indicate how to do the protect/unprotect
static bool use_exec_prot = true;

static int protect(void *addr, size_t len)
{
	if(use_exec_prot)
	{
		return mprotect(addr,len,PROT_READ|PROT_EXEC);
	}
	else //try doing in a 2 step fashion
	{
		mprotect(addr,len,PROT_READ);
		return mprotect(addr,len,PROT_READ|PROT_EXEC);
	}
}

//will try to unprotect with PROT_READ|PROT_WRITE|PROT_EXEC. If fails (might happen under SELinux) 
//will use PROT_READ|PROT_WRITE
static int unprotect(void *addr, size_t len)
{	
	int res;
	if(use_exec_prot)
	{
		res = mprotect(addr,len,PROT_READ|PROT_WRITE|PROT_EXEC);
		if(0 != res)
		{
			sql_print_information(
                "%s unable to unprotect. Page: %p, Size: %zu, errno: %d. Using NO EXEC mode.",
                log_prefix, (void *)addr, len, errno);
			use_exec_prot = false;
			//do a sanity test that we can actually unprotect/protect and that nx bit is off
			res = unprotect(addr, len);
			if(0 != res)
			{
			    sql_print_error(
                    "%s unable to unprotect page. This may happen if you have SELinux enabled. Disable SELinux execmod protection for mysqld. Aborting. Page: %p, Size: %zu, errno: %d.",
                    log_prefix, (void *)addr, len, errno);
			    return res;
			}
			res = protect(addr, len);
			if(0 != res)
            {
			    //fail only if nx bit is enabled
			    FILE * fp = fopen("/proc/cpuinfo", "r");
			    if(NULL == fp)
			    {
			        sql_print_error(
                        "%s unable to verify nx bit. Failed checking /proc/cpuinfo. This may happen if you have SELinux enabled. Disable SELinux execmod protection for mysqld. Aborting. Page: %p, Size: %zu, errno: %d.",
                        log_prefix, (void *)addr, len, errno);
			        return res;
			    }
			    char buff[1024] = {0};
			    const char * flags = "flags";
			    bool nxchecked = false;				
			    while(fgets(buff, 1024, fp) != NULL)
			    {
					char * line = buff;
					//trim white space at start
					while ((strlen(line) > 0) && (isspace(line[0])))
					{
						line++;
					}
			        if(strncmp(line, flags, strlen(flags)) == 0)
			        {
			            nxchecked = true;
			            sql_print_information("%s cpuinfo flags line: %s. ",log_prefix, line);
			            if(strstr(line, " nx")) //nx enabled so fail
			            {
			                sql_print_error(
                                "%s unable to protect page and nx bit enabled. This may happen if you have SELinux enabled. Disable SELinux execmod protection for mysqld. Aborting. Page: %p, Size: %zu.",
                                log_prefix, (void *)addr, len);
			                fclose(fp);
			                return res;
			            }
			            break;
			        }
			    }
			    fclose(fp);
			    if(!nxchecked) //we didn't find flags string for some reason
			    {
			        sql_print_error(
                        "%s unable to verify nx bit. Failed finding: %s in /proc/cpuinfo. This may happen if you have SELinux enabled. Disable SELinux execmod protection for mysqld. Aborting. Page: %p, Size: %zu.",
                        log_prefix, flags, (void *)addr, len);
	                return res;
			    }
            }
		}
		else //all is good
		{
			return res;
		}
	}
	res = mprotect(addr,len,PROT_READ|PROT_WRITE);
	if(0 != res) //log the failure
	{
		sql_print_error(
			"%s unable to unprotect. Page: %p, Size: %zu, errno: %d. Error.",
			log_prefix, (void *)addr, len, errno);
	}
	return res;		
}

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

unsigned int jump_size()
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

    //DWORD dwBuf = 0;    // nessary othewrise the function fails

    protect((void*)AddressPage, PAGE_SIZE);
}

//
// Hooks a function
//
static bool  HookFunction(ULONG_PTR targetFunction, ULONG_PTR newFunction, ULONG_PTR trampolineFunction, 
	unsigned int *trampolinesize)
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
    ud_set_pc(&ud_obj, targetFunction);

    DWORD InstrSize = 0;
    DATATYPE_ADDRESS trampolineFunctionPage = get_page_address((void*)trampolineFunction);
    if(unprotect((void*)trampolineFunctionPage, PAGE_SIZE) != 0)
	{
		sql_print_error(
                "%s unable to unprotect trampoline function page: %p. Aborting.",
                log_prefix, (void *)trampolineFunctionPage);
		return false;
	}
    bool disassemble_valid = false;
    while (ud_disassemble(&ud_obj))
    {
        if(ud_obj.mnemonic == UD_Iinvalid)
        {
            sql_print_error(
                "%s unable to disassemble at address: %p. Aborting.",
                log_prefix, (void *)(InstrSize + targetFunction));
            break;
        }
        //make sure there isn't a jmp/call (or similar operand) as these use
        //relative addressing and if we copy as is we will mess up the jmp/call target
        if(ud_obj.mnemonic == UD_Ijmp || ud_obj.mnemonic == UD_Icall ||
           ud_obj.operand[0].type == UD_OP_JIMM)
        {
            sql_print_error(
                "%s unable to disassemble at address: 0x%p. Found relative addressing for instruction: [%s]. Aborting.",
                log_prefix, (void *)(InstrSize + targetFunction), ud_insn_asm(&ud_obj));
            break;
        }

        BYTE *pCurInstr = (BYTE *) (InstrSize + (ULONG_PTR) targetFunction);
        memcpy((BYTE*)trampolineFunction + uCurrentSize,
                (void *) pCurInstr, ud_insn_len (&ud_obj));

        uCurrentSize += ud_insn_len (&ud_obj);
        InstrSize += ud_insn_len (&ud_obj);
        if (InstrSize >= jump_size()) //we have enough space so break
        {
            disassemble_valid = true;
            break;
        }
    }
    protect((void*)trampolineFunctionPage, PAGE_SIZE);
    if(!disassemble_valid) //something went wrong. log was written before so return false
    {
        return false;
    }
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
    if(unprotect((void*)FunctionPage, PAGE_SIZE) != 0)
	{
		sql_print_error(
                "%s Unhook not able to unprotect function page: %p. Aborting.",
                log_prefix, (void * )FunctionPage);
		return;
	}
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
 * 			which contains a bunch of nops. 
 * @param info_print if true will print info as progressing
 * @Return 0 on success otherwise failure
 * @See MS Detours paper: http://research.microsoft.com/pubs/68568/huntusenixnt99.pdf for some background info.
 */
int hot_patch_function (void* targetFunction, void* newFunction, void * trampolineFunction, unsigned int *trampolinesize, bool info_print)
{
	DATATYPE_ADDRESS trampolinePage = get_page_address(trampolineFunction);
	cond_info_print(info_print, "%s hot patching function: %p, trampolineFunction: %p trampolinePage: %p",log_prefix, (void *)targetFunction, (void *)trampolineFunction, (void *)trampolinePage);
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
void remove_hot_patch_function (void* targetFunction, void * trampolineFunction, unsigned int trampolinesize, bool info_print)
{
	if(trampolinesize == 0)
	{
		//nothing todo. As hot patch was not set.
		return;
	}
	DATATYPE_ADDRESS targetPage = get_page_address(targetFunction);
	cond_info_print(info_print, "%s removing hot patching function: %p targetPage: %p trampolineFunction: %p",log_prefix, (void *)targetFunction, (void *)targetPage, (void *)trampolineFunction);
	UnhookFunction ((ULONG_PTR) targetFunction, (ULONG_PTR)trampolineFunction,trampolinesize);
	return;	
}
