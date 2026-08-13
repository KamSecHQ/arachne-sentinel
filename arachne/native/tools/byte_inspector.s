// byte_inspector.s -- Arachne Sentinel bagimsiz native imza tarayici (Apple Silicon / ARM64)
//
// Projenin geri kalanindan tamamen bagimsiz, tek basina calisan bir ikili
// (binary). Bir dosyayi okur, bilinen 5 saldiri imzasina (SQLi/XSS/path
// traversal/command injection alt kumesi) karsi arar ve kisa bir rapor basar.
//
// Bu, "orumcek agi" fikrinin somut, savunulabilir hali: gercek dosya G/C'si
// (fopen/fread/fclose), gercek arguman/format string cagirma kurallari
// (AAPCS64) ve gercek bir arama algoritmasi (az_find, fast_scan.s ile ayni
// mantik) - hepsi elle yazilmis ARM64 assembly.
//
// Derleme (Mac, Apple Silicon):
//   clang -arch arm64 -o build/byte_inspector byte_inspector.s
// (bkz. Makefile)
//
// Kullanim:
//   ./byte_inspector <dosya_yolu>
//
// Not: Mantik once Linux ARM64 uzerinde (qemu-aarch64, gercek CPU emulasyonu)
// ayni fopen/fread/fclose/printf cagri sirasiyla dogrulandi (underscore'suz
// sembol isimleriyle); Mach-O/Apple clang icin sembol on-eki "_" ve
// @PAGE/@PAGEOFF adreslemesi disinda, ASAGIDAKI ONEMLI FARK da uygulandi:
//
// Apple'in ARM64 ABI'si, standart AAPCS64'ten (Linux'un kullandigi) burada
// SAPMA yapiyor: degisken argumanli (variadic) fonksiyonlarda (printf gibi)
// format string disindaki TUM argumanlar x1/x2/... register'lari yerine
// STACK'e (8 byte hizali sekilde) konmak zorunda. Linux/glibc'de register
// uzerinden gecirmek de calisiyordu (qemu testinde bu yuzden fark
// edilmedi), ama Mac'in libSystem printf'i argumanlari stack'ten okuyor -
// register'da birakilirsa printf çöp deger okur. Asagidaki her printf
// cagrisindan once degisken argumanlar sub/str ile stack'e yaziliyor.

    .data
usage_msg:
    .asciz "kullanim: byte_inspector <dosya_yolu>\n"
open_fail_msg:
    .asciz "HATA: dosya acilamadi: %s\n"
read_mode:
    .asciz "rb"
report_header:
    .asciz "== Arachne Sentinel Native Byte Inspector (ARM64 asm) ==\n"
report_size:
    .asciz "dosya boyutu     : %ld byte\n"
report_sig_hit:
    .asciz "  [BULUNDU] %s\n"
report_sig_miss:
    .asciz "  [temiz]   %s\n"
report_footer:
    .asciz "toplam %d/%d bilinen imza eslesti\n"

sig_sqli:      .asciz "' or '1'='1"
sig_union:     .asciz "union select"
sig_xss:       .asciz "<script>"
sig_traversal: .asciz "../../../"
sig_cmdinj:    .asciz "$("

name_sqli:      .asciz "SQL Injection (' or '1'='1)"
name_union:     .asciz "SQL Injection (union select)"
name_xss:       .asciz "XSS (<script>)"
name_traversal: .asciz "Path Traversal (../../../)"
name_cmdinj:    .asciz "Command Injection ($()"

    .align 3
needle_ptrs:
    .quad sig_sqli, sig_union, sig_xss, sig_traversal, sig_cmdinj
needle_lens:
    .quad 11, 12, 8, 9, 2
    .align 3
name_ptrs:
    .quad name_sqli, name_union, name_xss, name_traversal, name_cmdinj

    .comm filebuf, 1048576, 4     // 1 MiB statik okuma tamponu (bss)

    .text
    .global _az_find
    .align 4

// int64_t az_find(const uint8_t *hay, int64_t hay_len,
//                  const uint8_t *needle, int64_t needle_len)
// -- fast_scan.s ile birebir ayni algoritma (bkz. orada ki yorumlar).
_az_find:
    cmp     x3, #0
    beq     .Lfind_empty_needle
    cmp     x3, x1
    bgt     .Lfind_not_found
    mov     x4, #0
    sub     x5, x1, x3
.Lfind_outer:
    cmp     x4, x5
    bgt     .Lfind_not_found
    mov     x6, #0
.Lfind_inner:
    cmp     x6, x3
    beq     .Lfind_match
    add     x7, x0, x4
    ldrb    w8, [x7, x6]
    ldrb    w9, [x2, x6]
    cmp     w8, w9
    bne     .Lfind_next
    add     x6, x6, #1
    b       .Lfind_inner
.Lfind_next:
    add     x4, x4, #1
    b       .Lfind_outer
.Lfind_match:
    mov     x0, x4
    ret
.Lfind_not_found:
    mov     x0, #-1
    ret
.Lfind_empty_needle:
    mov     x0, #0
    ret

    .global _main
    .align 4
_main:
    // x0 = argc, x1 = argv
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]

    cmp     x0, #2
    bge     .Lmain_have_arg
    adrp    x0, usage_msg@PAGE
    add     x0, x0, usage_msg@PAGEOFF
    bl      _printf
    mov     w0, #1
    b       .Lmain_exit

.Lmain_have_arg:
    ldr     x19, [x1, #8]          // argv[1]

    adrp    x1, read_mode@PAGE
    add     x1, x1, read_mode@PAGEOFF
    mov     x0, x19
    bl      _fopen
    mov     x20, x0                 // FILE* -> x20
    cbnz    x20, .Lmain_opened
    sub     sp, sp, #16              // Apple ABI: variadic argumanlar stack'te
    str     x19, [sp]
    adrp    x0, open_fail_msg@PAGE
    add     x0, x0, open_fail_msg@PAGEOFF
    bl      _printf
    add     sp, sp, #16
    mov     w0, #1
    b       .Lmain_exit

.Lmain_opened:
    adrp    x0, report_header@PAGE
    add     x0, x0, report_header@PAGEOFF
    bl      _printf

    // fread(filebuf, 1, 1048576, fp)
    adrp    x0, filebuf@PAGE
    add     x0, x0, filebuf@PAGEOFF
    mov     x1, #1
    mov     x2, #1048576
    mov     x3, x20
    bl      _fread
    mov     x21, x0                 // okunan byte sayisi -> x21

    mov     x0, x20
    bl      _fclose

    sub     sp, sp, #16              // Apple ABI: variadic argumanlar stack'te
    str     x21, [sp]
    adrp    x0, report_size@PAGE
    add     x0, x0, report_size@PAGEOFF
    bl      _printf
    add     sp, sp, #16

    mov     x19, #0                 // eslesen imza sayaci
    mov     x22, #0                 // i = 0
.Lscan_loop:
    cmp     x22, #5
    bge     .Lscan_done

    adrp    x9, needle_ptrs@PAGE
    add     x9, x9, needle_ptrs@PAGEOFF
    lsl     x10, x22, #3
    ldr     x2, [x9, x10]           // needle isaretcisi

    adrp    x9, needle_lens@PAGE
    add     x9, x9, needle_lens@PAGEOFF
    ldr     x3, [x9, x10]           // needle uzunlugu

    adrp    x0, filebuf@PAGE
    add     x0, x0, filebuf@PAGEOFF
    mov     x1, x21                 // hay_len = okunan byte sayisi
    bl      _az_find

    adrp    x9, name_ptrs@PAGE
    add     x9, x9, name_ptrs@PAGEOFF
    ldr     x1, [x9, x10]           // imza adi

    cmp     x0, #0
    blt     .Lscan_miss
    add     x19, x19, #1
    sub     sp, sp, #16              // Apple ABI: variadic argumanlar stack'te
    str     x1, [sp]
    adrp    x0, report_sig_hit@PAGE
    add     x0, x0, report_sig_hit@PAGEOFF
    bl      _printf
    add     sp, sp, #16
    b       .Lscan_next
.Lscan_miss:
    sub     sp, sp, #16              // Apple ABI: variadic argumanlar stack'te
    str     x1, [sp]
    adrp    x0, report_sig_miss@PAGE
    add     x0, x0, report_sig_miss@PAGEOFF
    bl      _printf
    add     sp, sp, #16
.Lscan_next:
    add     x22, x22, #1
    b       .Lscan_loop

.Lscan_done:
    sub     sp, sp, #16              // Apple ABI: variadic argumanlar stack'te (2x 8 byte slot)
    mov     w9, w19
    str     x9, [sp]
    mov     w9, #5
    str     x9, [sp, #8]
    adrp    x0, report_footer@PAGE
    add     x0, x0, report_footer@PAGEOFF
    bl      _printf
    add     sp, sp, #16

    mov     w0, #0

.Lmain_exit:
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret
