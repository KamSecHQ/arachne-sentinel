// fast_scan.s -- Arachne Sentinel native imza tarama cekirdegi (Apple Silicon / ARM64)
//
// Bu dosya, honeypot ve WAF kural motorlarinin merkezinde yer alan "bu payload
// icinde bilinen bir saldiri imzasi var mi?" sorusunu, elle yazilmis ARM64
// assembly ile cevaplayan iki fonksiyon icerir. Amac "100 katmanli sihirli
// bir savunma" degil; projenin GERCEKTEN kullandigi, test edilmis, olculebilir
// bir dusuk seviye bilesen eklemek (bkz. docs/ROADMAP.md - Faz 3).
//
// Derleme (Mac, Apple Silicon / M-serisi):
//   clang -arch arm64 -shared -o build/libaz_fast_scan.dylib fast_scan.s
// (bkz. Makefile)
//
// ABI: AAPCS64 (standart ARM64 cagirma kurali), C ile dogrudan uyumlu.
// Bu dosyada disaridan cagrilan libc fonksiyonu YOK - sadece kayitlar (register)
// ve bellek uzerinde calisir, bu yuzden Mach-O harici sembol/underscore
// karmasasi (bkz. tools/byte_inspector.s) burada soz konusu degil.
//
// Mantik once Linux ARM64 (qemu-aarch64 ile gercek CPU emulasyonu) uzerinde
// 20.000+ rastgele (fuzz) test ve el ile yazilmis kenar durum testleriyle
// dogrulandi, ardindan Mach-O/Apple clang icin sembol isimleri (_ on eki)
// disinda DEGISTIRILMEDEN buraya tasindi.

    .text
    .global _az_find
    .align 4

// int64_t az_find(const uint8_t *hay, int64_t hay_len,
//                  const uint8_t *needle, int64_t needle_len)
//
// hay icinde needle'in ilk gectigi index'i dondurur, bulunamazsa -1.
// Bos needle her zaman index 0'da "eslesir" (C'nin strstr davranisiyla ayni).
// needle_len > hay_len ise dogrudan "bulunamadi" sonucu dondurur.
_az_find:
    cmp     x3, #0
    beq     .Lfind_empty_needle
    cmp     x3, x1
    bgt     .Lfind_not_found

    mov     x4, #0              // i = 0 (hay icindeki baslangic offseti)
    sub     x5, x1, x3          // gecerli son baslangic index'i = hay_len - needle_len
.Lfind_outer:
    cmp     x4, x5
    bgt     .Lfind_not_found
    mov     x6, #0              // j = 0 (needle icindeki offset)
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

    .global _az_scan_multi
    .align 4

// int32_t az_scan_multi(const uint8_t *buf, int64_t buf_len,
//                        const uint8_t **needles, const int64_t *needle_lens,
//                        int32_t n_needles)
//
// buf icinde needles[0..n_needles) dizisindeki imzalari arar; bit i set ise
// needles[i] bulunmus demektir. En fazla 32 imza desteklenir (bitmask genisligi).
_az_scan_multi:
    stp     x29, x30, [sp, #-80]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]

    mov     x19, x0             // buf
    mov     x20, x1             // buf_len
    mov     x21, x2             // needles isaretci dizisi
    mov     x22, x3             // needle_lens dizisi
    mov     w23, w4             // n_needles (x23'e sifir-genisletilmis olarak yazilir)
    mov     w24, #0             // bitmask biriktirici
    mov     x25, #0             // i = 0

.Lscan_loop:
    cmp     x25, x23
    bge     .Lscan_done
    lsl     x10, x25, #3        // i * 8 (pointer/int64 dizi adimi)
    ldr     x2, [x21, x10]      // needles[i]
    ldr     x3, [x22, x10]      // needle_lens[i]
    mov     x0, x19             // hay = buf
    mov     x1, x20             // hay_len = buf_len
    bl      _az_find
    cmp     x0, #0
    blt     .Lscan_next
    cmp     x25, #31
    bgt     .Lscan_next         // guvenlik siniri: 32'den fazla imzada fazlasini yok say
    mov     x11, #1
    lsl     x11, x11, x25
    orr     w24, w24, w11
.Lscan_next:
    add     x25, x25, #1
    b       .Lscan_loop
.Lscan_done:
    mov     w0, w24
    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #80
    ret
