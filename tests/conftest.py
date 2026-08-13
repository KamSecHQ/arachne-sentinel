import sys
from pathlib import Path

# Testler nereden calistirilirsa calistirilsin proje kokunun import edilebilir
# olmasini garanti eder.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
