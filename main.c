#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

#define OBF_KEY 0xAA
#define X(x) ((x) ^ OBF_KEY)
#define OBF_LOOP(arr) for (size_t i = 0; (arr)[i] != 0; i++)

// Define a function pointer type for printf.
typedef int (*printf_t)(const char*, ...);

// Simple XOR decryption: decrypts data in place.
void xor_decrypt(char *data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

static inline void OBF_DEC(uint8_t *d) {
    OBF_LOOP(d) {
        d[i] = X(d[i]);
    }
}

printf_t hidden_printf = 0;
HMODULE msvcrt = 0;

// Obscure function that decrypts the message and prints "Hello, World!"
// It then calls exit() so that the altered return path does not lead to undefined behavior.
int _0xBEEF() {
    // "Hello, World!\n" XOR'd with 0xAA
    uint8_t _0xBAD[15] = {0xE2, 0xCF, 0xC6, 0xC6, 0xC5, 0x86, 0x8A, 0xFD,
                           0xC5, 0xD8, 0xC6, 0xCE, 0x8B, 0xA0, 0x00};
    __asm__("nop"); // Insert a no-op to further confuse disassemblers
    OBF_DEC(_0xBAD);
    // int r = printf("FUCK");
    // exit(r);
    const char *msg = _0xBAD;
    __asm__ volatile (
        "mov %[fp], %%rax\n"    // Move function pointer into RAX.
        "mov %[msg], %%rcx\n"   // Set RCX (first argument) to point to our message.
        "xor %%rdx, %%rdx\n"    // Clear RDX (second argument, unused here).
        "xor %%r8, %%r8\n"      // Clear R8.
        "xor %%r9, %%r9\n"      // Clear R9.
        "call *%%rax\n"         // Indirectly call printf via the function pointer in RAX.
        :
        : [fp] "r" (hidden_printf), [msg] "r" (msg)
        : "rax", "rcx", "rdx", "r8", "r9"
    );
    FreeLibrary(msvcrt);
    exit(EXIT_SUCCESS);
}

// Trampoline function: it manipulates the stack so that when it returns,
// control is transferred to _0xBEEF without an explicit call.
__attribute__((naked)) void trampoline() {
    __asm__ volatile (
        "pop %rax\n"              "\n\t"  // Remove the original return address
        "movabs $_0xBEEF, %rcx\n"  "\n\t"  // Load the address of _0xBEEF into rcx
        "push %rcx\n"             "\n\t"  // Push _0xBEEF's address as the new return address
        "ret\n"                          // Return, jumping to _0xBEEF
    );
}

// main uses the trampoline to indirectly transfer control to _0xBEEF.
int main(int argc, char **argv)
{
    int cd = argc - (int)((unsigned long long int)argv & 0xFFFFFFFF);
    // Load the Microsoft C runtime library.
    msvcrt = LoadLibraryA("msvcrt.dll");
    if (!msvcrt) {
        return EXIT_FAILURE;
    }

    // Encrypted "printf" using XOR with key 0xAA.
    // For example, 'p' (0x70) ^ 0xAA = 0xDA.
    char enc_name[] = { 0xDA, 0xD8, 0xC3, 0xC4, 0xDE, 0xCC, 0x00 };

    // Decrypt in place so that the literal "printf" does not appear in the binary.
    xor_decrypt(enc_name, 6, 0xAA);
    // Get the function pointer for printf from msvcrt.dll.
    hidden_printf = (printf_t) GetProcAddress(msvcrt, enc_name);
    if (!hidden_printf) {
        FreeLibrary(msvcrt);
        return EXIT_FAILURE;
    }
    trampoline();
    exit(0);
    return 0; // Unreachable because _0xBEEF calls exit()
}
