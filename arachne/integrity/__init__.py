"""
Faz 17 - Butunluk ve kurcalama-kaniti (tamper-evidence) katmani.

Bir guvenlik sisteminin kendi kayitlari, korudugu sistemler kadar
degerlidir. Bir saldirgan sisteme sizarsa yapacagi ilk seylerden biri
IZLERINI SILMEKTIR - denetim kayitlarini degistirmek ya da silmek.

Bu katman, kayitlarin degistirilip degistirilmedigini KANITLANABILIR hale
getirir: her kayit, kendinden oncekinin hash'ini icerir (hash zinciri).
Tek bir kaydin degistirilmesi, sonraki tum hash'leri bozar - tam olarak
bir blok zincirinin (blockchain) calisma mantigi, ama merkezi ve hafif.

Ayrica bir Merkle agaci koku ile, tum kayit kumesinin tek bir parmak izini
uretiriz - bu koku ayri/guvenli bir yere yazip periyodik dogrulama yapmak,
kurcalamayi tespit etmenin standart yoludur.
"""

from .audit_chain import (
    AuditChain,
    merkle_root,
    verify_chain,
)

__all__ = ["AuditChain", "merkle_root", "verify_chain"]
