import os
import sys
from pathlib import Path

# Testler nereden calistirilirsa calistirilsin proje kokunun import edilebilir
# olmasini garanti eder.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Faz 117: panel kimlik dogrulamasi varsayilan ACIK. Panel API'sini test eden
# mevcut testler oturumsuz calisir; kimlik dogrulamanin kendisi
# tests/test_panel_auth.py'de ARACHNE_PANEL_AUTH=1 ile test edilir.
os.environ.setdefault("ARACHNE_PANEL_AUTH", "0")
