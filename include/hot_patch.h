/*
 * hot_patch.h
 *
 *  Created on: Jan 10, 2011
 *      Author: Guyl
 */

#ifndef HOT_PATCH_H_
#define HOT_PATCH_H_

#include "mysql_inc.h"

#define DATATYPE_ADDRESS unsigned long
/*
#define JMP_OPCODE 0xE9
#define OPCODE_LENGTH 1

#define ADDRESS_LENGTH (sizeof(DATATYPE_ADDRESS))
#define MIN_REQUIRED_FOR_DETOUR (OPCODE_LENGTH + ADDRESS_LENGTH)
//the lenght of code we copy from target function to trampoline function (must be larger from MIN_REQUIRED_FOR_DETOUR=5).
//Using 6 as this is what is used in other sample code I've seen
#define TRAMPOLINE_COPY_LENGTH 6
*/

#define TRAMPOLINE_NOP_DEF {asm("nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t"\
        "nop\n\t");\
        }

int hot_patch_function(void* targetFunction, void* newFunction, void * trampolineFunction, unsigned int *trampolinesize, bool log_info, const char * log_prefix);

void remove_hot_patch_function (void* targetFunction, void * trampolineFunction, unsigned int trampolinesize, bool log_info, const char * log_prefix);

#endif /* HOT_PATCH_H_ */
