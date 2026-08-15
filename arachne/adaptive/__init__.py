"""
Faz 21-30 - Adaptif Savunma katmani (ADAPTIVE DEFENSE).

--- Bu paketin tezi: KO-EVRIM (co-evolution) ---
Onceki fazlar (1-20) "saldiriyi gor, skorla, durdur, kaydet" hattiydi. Bu
paket bir adim oteye gecer: saldirgan bizim savunmamizi GOZLEYIP taktik
degistirirse, savunma da ona gore ADAPTE OLUR. Yani statik bir duvar degil,
saldirganla birlikte evrilen bir savunma.

Her modul gercek, adiyla anilan bir savunma cercevesine dayanir (uydurma
degil): MITRE D3FEND / Engage, NIST SP 800-207 (Sifir Guven), NIST CSF 2.0,
Moving Target Defense, Stackelberg guvenlik oyunlari, JA3/JA4 parmak izi,
CUSUM/EWMA istatistiksel kayma tespiti.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Bu katman da tamamen SAVUNMADIR. Hicbir modul baska bir sisteme saldirmaz
(hack-back yoktur). Tum eylemler kendi izleme yuzeyimizde kalir. "Adaptif"
olmak, karsi saldiri degil; kendi savunma yapilandirmamizi saldirganin
davranisina gore yeniden duzenlemek demektir.

--- DURUSTLUK ---
Modeller kucuk olcekli, deterministik/istatistiksel/graf/kural tabanlidir;
ML egitimi gerektirmez. Amac, gercek kurumsal/ulusal savunma sistemlerinin
CEKIRDEK MANTIGINI dogru ve aciklanabilir sekilde gostermektir - o urunlerin
tam olcekli kopyasi degil.
"""
