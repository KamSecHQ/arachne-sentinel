FROM python:3.12-slim

LABEL maintainer="Arachne Sentinel"
LABEL description="Honeypot tabanli SOC platformu - SADECE izole/lab ortaminda calistirin (bkz. docs/ETHICS_AND_LEGAL.md)"

WORKDIR /app

# Faz 3'un elle yazilmis ARM64 assembly cekirdegi (arachne/native/) bu imajda
# DERLENMEZ - konteyner platformu farkli olabilir. Sistem bunu algilar ve
# otomatik/sessizce Python yedegine duser (arachne/native/signature_engine.py);
# davranis hicbir zaman degismez, sadece hiz degisir (bkz. proje README'si).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Root olmayan kullanici: honeypot servisleri zaten kok yetkisi gerektirmeyen
# portlarda calisacak sekilde tasarlandi (bkz. arachne/config.py), bu yuzden
# konteyner icinde de root gerekmez.
RUN useradd --create-home --shell /bin/bash arachne \
    && mkdir -p /app/data \
    && chown -R arachne:arachne /app
USER arachne

# Dashboard + honeypot servisleri (Faz 1-103) + hayalet DNS (udp, GERCEK
# sistem DNS'i degil - bkz. docs/ETHICS_AND_LEGAL.md)
EXPOSE 5001 2222 2121 3307 8081 2323 6380 2375 9200 3389 4450 5300/udp

ENTRYPOINT ["python", "main.py"]
CMD ["dashboard", "--port", "5001", "--no-open"]
