"""
Faz 7 - SOAR: Otonom Savunma Orkestrasyonu.

SOAR = Security Orchestration, Automation and Response.

Faz 1-6 saldiriyi GORUR ve ANLAR. Bu katman ise ona TEPKI VERIR - hem de
insan mudahalesi beklemeden, saniyeler icinde.

Boru hatti (ticari SOAR urunlerinin ortak sozlugu):

    TETIKLEYICI -> ZENGINLESTIRME -> KARAR -> EYLEM -> KAPANIS

Moduller:
  playbooks.py - playbook tanimlari (saf veri, kod degil)
  engine.py    - playbook calistirma motoru
  actions.py   - mudahale eylemleri (zenginlestirme / kisitlama ayrimiyla)
  blocklist.py - TTL'li gercek yaptirim mekanizmasi

--- Bu katmanin en onemli tasarim ilkesi ---
Otomasyon olgunlugu "her seyi otomatiklestirmek" DEGILDIR; insan onay
kapisinin nereye konulacagini bilmektir. Geri alinabilir eylemler (sureli
engelleme) otomatik; geri alinamaz ya da yikici eylemler insan onayi
gerektirir. Ayni ilke, Faz 8'deki yapay zeka katmani icin daha da katidir:
AI ciktisi HICBIR ZAMAN dogrudan bir kisitlama tetikleyemez.
"""

from .blocklist import active_blocks, block, is_blocked, unblock
from .engine import respond_to_alert, run_playbook
from .playbooks import PLAYBOOKS, find_matching_playbooks, playbook_summary

__all__ = [
    "PLAYBOOKS",
    "find_matching_playbooks",
    "playbook_summary",
    "respond_to_alert",
    "run_playbook",
    "block",
    "unblock",
    "is_blocked",
    "active_blocks",
]
