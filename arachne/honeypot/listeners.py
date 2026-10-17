"""
Sahte servisleri (honeypot) asyncio ile ayaga kaldirir.

Her servis gercek bir sistem gibi davranan minimal bir banner gonderir,
gelen veriyi kisa bir sure dinler, storage'a kaydeder ve baglantiyi kapatir.
HICBIR GERCEK KOMUT CALISTIRILMAZ, dosya sistemine erisim verilmez - bu
tamamen pasif, "dusuk etkilesimli" (low-interaction) bir honeypot'tur.
Sadece izole/lab ortaminda calistirin (bkz. docs/ETHICS_AND_LEGAL.md).
"""
import asyncio
import logging
import random

from .. import config
from .. import storage
from ..detection import scorer

logger = logging.getLogger("arachne.honeypot")

# Faz 108 - anti-parmak-izi: yanit gecikmesi.
# Deterministik/sabit bir gecikme (ya da hic gecikme olmamasi) zamanlama
# analiziyle "bu bir honeypot" tespitine acik kapi birakir - gercek bir
# sunucu yuke gore DEGISKEN gecikir. Bilincli olarak GERCEK rastgelelik
# kullanilir (guvenlik-kritik bir baglam degil, sadece gerceklik hissi).
_JITTER_MIN_SECONDS = 0.02
_JITTER_MAX_SECONDS = 0.15


async def _response_jitter():
    await asyncio.sleep(random.uniform(_JITTER_MIN_SECONDS, _JITTER_MAX_SECONDS))


def _peer_info(writer):
    peer = writer.get_extra_info("peername")
    return (peer[0], peer[1]) if peer else ("unknown", None)


def _is_blocked(source_ip):
    """SOAR engelleme listesini sorgular (sicak yol - her baglantida cagrilir).

    Tembel import: soar paketi yuklenemezse honeypot yine de calisir."""
    try:
        from ..soar import blocklist
        return blocklist.is_blocked(source_ip)
    except Exception:
        return False


def _check_honeytokens(source_ip, payload):
    """Faz 12: gelen yukte tetiklenmis bir honeytoken var mi?

    Bir honeytoken tetiklenmesi neredeyse kesin bir ihlal kanitidir -
    mesru kullanicilar bu tuzak degerlerin varligini bilmez."""
    try:
        from ..active_defense.honeytokens import check_payload_for_tokens
        result = check_payload_for_tokens(payload)
        if result["high_confidence_breach"]:
            logger.warning("HONEYTOKEN TETIKLENDI! kaynak=%s (%d token)",
                           source_ip, result["count"])
    except Exception:
        logger.debug("Honeytoken kontrolu basarisiz", exc_info=True)


async def _read_payload(reader):
    try:
        data = await asyncio.wait_for(
            reader.read(config.MAX_PAYLOAD_BYTES), timeout=config.READ_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        data = b""
    return data.decode(errors="replace") if data else None


async def _close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


# --- Faz 116: Son Hat aldatma karantinasi ------------------------------------
# Son Hat gercek sinyalle acildiginda hedef IP burada REDDEDILMEZ: ret,
# saldirgana "yakalandin" der. Bunun yerine tarpit ile yavaslatilir ve yalnizca
# aldatma icerigi alir. Karar panel surecinde verilir, durum veritabanindan
# okunur (bkz. arachne/lastline/enforcement.py).

def _is_quarantined(source_ip):
    try:
        return storage.is_lastline_quarantined(source_ip)
    except Exception:
        return False


def _quarantine_delay():
    """Faz 11 tarpit politikasinin en ust kademesi (en yuksek tehdit + tekrar)."""
    from ..active_defense.tarpit import compute_tarpit_delay
    return compute_tarpit_delay(threat_score=100, prior_alerts=1)["delay"]


async def _tarpit_write(writer, data: bytes, delay: float):
    """Endlessh mantigi: yaniti tek seferde degil, tarpit suresine yayarak yollar."""
    from ..active_defense.tarpit import tarpit_banner_stream
    for chunk, pause in tarpit_banner_stream(data.decode("latin-1"), delay):
        writer.write(chunk.encode("latin-1"))
        await writer.drain()
        await asyncio.sleep(pause)


def _quarantine_http_response(source_ip):
    """Karantinadaki saldirgana sahte 'giris basarili' paneli (Faz 108 cekirdek
    yemiyle ayni ilke). Kimlikler uydurmadir; 'SAHTE' notu bilerek gonderilmez."""
    from ..active_defense.deception import generate_fake_credentials
    rows = "".join(f"<tr><td>{c['username']}</td><td>{c['password']}</td></tr>"
                   for c in generate_fake_credentials(source_ip, count=2))
    body = ("<html><head><title>Admin Panel</title></head><body>"
            "<h2>Hos geldiniz, admin</h2><p>Servis hesaplari:</p>"
            f"<table>{rows}</table></body></html>").encode()
    return (b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Content-Type: text/html; charset=utf-8\r\n"
            + b"Connection: close\r\n\r\n" + body)


async def _serve_quarantine(service_name, dest_port, reader, writer, source_ip,
                            source_port, banner: bytes = b"", respond=None):
    """Karantinadaki baglanti: banner/yanit tarpit ile yavas akar. Olay
    'quarantine' tipinde loglanir ve yeniden skorlanmaz - karar zaten verildi."""
    logger.info("KARANTINA: %s -> %s (Son Hat aldatma kuyusu)", source_ip, service_name)
    payload = None
    delay = _quarantine_delay()
    try:
        if banner:
            await _tarpit_write(writer, banner, delay)
        payload = await _read_payload(reader)
        if payload:
            _check_honeytokens(source_ip, payload)
        response = respond(payload or "") if respond else None
        if response:
            await _tarpit_write(writer, response, delay)
    finally:
        storage.log_event(source_ip, service_name, "quarantine", source_port=source_port,
                          dest_port=dest_port, payload=payload)
        await _close(writer)


def _attack_classes_for_ip(source_ip):
    """SOAR playbook secimi icin bu IP'nin saldiri siniflarini belirler.

    Faz 5'in tersine muhendislik motorunu kullanir; boylece SOAR, sadece
    skora degil saldirinin TURUNE gore de playbook secebilir."""
    try:
        from ..reverse.attack_analyzer import analyze_ip
        events = storage.get_recent_events(source_ip=source_ip,
                                            since_seconds=config.DEFAULT_LOOKBACK_SECONDS)
        return analyze_ip(source_ip, events).get("attack_classes", [])
    except Exception:
        logger.debug("Saldiri sinifi analizi basarisiz", exc_info=True)
        return []


def _evaluate_and_log_alarm(source_ip, soar_enabled=False):
    result = scorer.evaluate_ip(source_ip)
    if result["triggered_alert"]:
        logger.warning(
            "ALARM! kaynak=%s skor=%s siddet=%s sebepler=%s",
            source_ip, result["score"], result["severity"], result["reasons"],
        )
        # Faz 7: otonom mudahale. Varsayilan olarak KAPALIdir - Faz 1-3
        # davranisi hicbir sekilde degismesin diye. `soar-demo` komutu ile
        # acikca etkinlestirilir.
        if soar_enabled:
            attack_classes = _attack_classes_for_ip(source_ip)
            try:
                from ..soar.engine import respond_to_alert
                response = respond_to_alert(
                    source_ip, result["score"], result["severity"],
                    attack_classes=attack_classes,
                )
                if response.get("matched_playbooks"):
                    logger.warning("SOAR: %s", response["summary_tr"])
            except Exception:
                logger.exception("SOAR mudahalesi basarisiz")

            # Faz 11: aktif savunma (tarpit/aldatma karari) - saldirgani
            # kendi honeypot'umuzda oyalar. BASKA SISTEME DOKUNMAZ.
            try:
                from ..active_defense.deception import DeceptionEngine
                DeceptionEngine().apply(source_ip, result["score"], attack_classes)
            except Exception:
                logger.debug("Aktif savunma uygulanamadi", exc_info=True)
    return result


async def _handle_generic(service_name: str, dest_port: int, reader, writer,
                          rotator=None, soar_enabled=False):
    source_ip, source_port = _peer_info(writer)

    # Faz 4 (Moving Target Defense) aktifse rotator'dan zaman icinde degisen
    # banner'i kullan; aktif degilse (varsayilan) config.py'deki sabit
    # banner'i kullan - davranis Faz 1-3 ile birebir ayni kalir.
    banner = (rotator.current_banner(service_name) if rotator else None) \
        or config.FAKE_SERVICES[service_name].get("banner")

    # Faz 116: Son Hat karantinasi engelden ONCE gelir - ret yerine aldatma.
    if soar_enabled and _is_quarantined(source_ip):
        await _serve_quarantine(service_name, dest_port, reader, writer, source_ip,
                                source_port, banner=(banner or "").encode(errors="ignore"))
        return

    # Faz 7: engelli IP'ler icin baglanti aninda kapatilir. Bu, SOAR
    # katmaninin GERCEK yaptirim noktasidir - bir raporlama detayi degil,
    # gercekten uygulanan bir kisitlama.
    if soar_enabled and _is_blocked(source_ip):
        storage.log_event(source_ip, service_name, "blocked", source_port=source_port,
                           dest_port=dest_port)
        logger.info("ENGELLENDI: %s -> %s (SOAR kisitlamasi aktif)", source_ip, service_name)
        await _close(writer)
        return

    storage.log_event(source_ip, service_name, "connect", source_port=source_port,
                       dest_port=dest_port)
    logger.info("baglanti: %s -> %s (port %s)", source_ip, service_name, dest_port)

    try:
        if banner:
            await _response_jitter()
            writer.write(banner.encode(errors="ignore"))
            await writer.drain()

        payload = await _read_payload(reader)
        if payload:
            storage.log_event(source_ip, service_name, "data", source_port=source_port,
                               dest_port=dest_port, payload=payload)
            _check_honeytokens(source_ip, payload)
    finally:
        storage.log_event(source_ip, service_name, "disconnect", source_port=source_port,
                           dest_port=dest_port)
        await _close(writer)

    _evaluate_and_log_alarm(source_ip, soar_enabled=soar_enabled)


def _make_generic_handler(service_name: str, dest_port: int, rotator=None,
                          soar_enabled=False):
    async def handler(reader, writer):
        await _handle_generic(service_name, dest_port, reader, writer,
                              rotator=rotator, soar_enabled=soar_enabled)
    return handler


async def _handle_http_admin(dest_port: int, reader, writer, soar_enabled=False):
    """Sahte bir 'yonetici paneli' HTTP servisi - istekleri loglar, sahte bir
    giris formu doner. Girilen kullanici adi/sifre gercek hicbir sisteme
    gonderilmez, sadece loglanir (tuzak/deception amacli)."""
    source_ip, source_port = _peer_info(writer)

    if soar_enabled and _is_quarantined(source_ip):
        await _serve_quarantine("http-admin", dest_port, reader, writer, source_ip,
                                source_port,
                                respond=lambda _p: _quarantine_http_response(source_ip))
        return

    if soar_enabled and _is_blocked(source_ip):
        storage.log_event(source_ip, "http-admin", "blocked", source_port=source_port,
                           dest_port=dest_port)
        logger.info("ENGELLENDI: %s -> http-admin (SOAR kisitlamasi aktif)", source_ip)
        await _close(writer)
        return

    storage.log_event(source_ip, "http-admin", "connect", source_port=source_port,
                       dest_port=dest_port)

    try:
        payload = await _read_payload(reader)
        if payload:
            storage.log_event(source_ip, "http-admin", "data", source_port=source_port,
                               dest_port=dest_port, payload=payload)

        body = (
            "<html><head><title>Admin Panel</title></head><body>"
            "<h2>Yonetici Girisi</h2>"
            "<form method='POST'><input name='user' placeholder='kullanici'>"
            "<input name='pass' type='password' placeholder='sifre'>"
            "<button type='submit'>Giris</button></form></body></html>"
        )
        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n\r\n" + body
        )
        await _response_jitter()
        writer.write(response.encode())
        await writer.drain()
    finally:
        storage.log_event(source_ip, "http-admin", "disconnect", source_port=source_port,
                           dest_port=dest_port)
        await _close(writer)

    _evaluate_and_log_alarm(source_ip, soar_enabled=soar_enabled)


def _fake_http_response(body: str, status: str = "200 OK") -> str:
    """http-admin (Faz 1) ile ayni sekilde el ile kurulmus bir HTTP yaniti."""
    return (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n\r\n" + body
    )


def _redis_response(payload: str):
    """Faz 103: Redis RESP protokolunun kucuk, gerceci bir alt kumesi.

    Gercek Redis baglanti aninda banner GONDERMEZ (bu yuzden config.py'de
    banner=None) - sadece PING/INFO gibi taniyici komutlara gercekci yanit
    verir. Yanlislikla acik birakilmis Redis'ler gercek dunyada yaygin bir
    saldiri yuzeyidir (kimlik dogrulamasiz erisim, CONFIG SET ile RCE)."""
    text = (payload or "").upper()
    if not text:
        return None
    if "PING" in text:
        return b"+PONG\r\n"
    if "INFO" in text:
        info = ("# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
                "os:Linux 5.15.0\r\narch_bits:64\r\nprocess_id:1\r\n")
        return f"${len(info)}\r\n{info}\r\n".encode()
    return b"-ERR unknown command\r\n"


def _docker_api_response(payload: str):
    """Faz 103: Gercek Docker Remote API formatinda ama tamamen uydurma veri.

    Yanlislikla disariya acik birakilmis Docker daemon'lari (klasik ornek:
    2375/tcp kimlik dogrulamasiz), konteyner kacisi/host ele gecirme icin
    bilinen bir saldiri yuzeyidir - bu tuzak o senaryoyu simule eder."""
    request_line = (payload or "").splitlines()[0] if payload else ""
    if "/version" in request_line:
        body = ('{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux",'
                '"Arch":"amd64","KernelVersion":"5.15.0-generic"}')
        return _fake_http_response(body).encode()
    if "/containers/json" in request_line:
        return _fake_http_response("[]").encode()
    return _fake_http_response('{"message":"page not found"}', status="404 Not Found").encode()


def _elasticsearch_response(payload: str):
    """Faz 103: Kok isteğine sahte cluster/version bilgisi; digerlerine 404.

    Gelen sorgu govdesi (query DSL enjeksiyonu denemeleri dahil) her zaman
    payload olarak loglanir - yaniti bu fonksiyon uretse de veri kaybı yok."""
    request_line = (payload or "").splitlines()[0] if payload else ""
    if not request_line or request_line.startswith("GET / "):
        body = ('{"name":"arachne-node-1","cluster_name":"docker-cluster",'
                '"version":{"number":"8.11.3","lucene_version":"9.8.0"},'
                '"tagline":"You Know, for Search"}')
        return _fake_http_response(body).encode()
    body = ('{"error":{"root_cause":[{"type":"index_not_found_exception",'
           '"reason":"no such index"}]},"status":404}')
    return _fake_http_response(body, status="404 Not Found").encode()


# Bu servisler HTTP/RESP tabanli, isteğe gore gercekci bir yanit uretir -
# generic handler'in "sabit banner + tek okuma" kalibina uymazlar.
_BESPOKE_RESPONSE_BUILDERS = {
    "redis": _redis_response,
    "docker-api": _docker_api_response,
    "elasticsearch": _elasticsearch_response,
}


async def _handle_bespoke_service(service_name: str, dest_port: int, reader, writer,
                                  soar_enabled: bool, build_response):
    """Faz 103: banner göndermeyen, isteğe göre gerçekçi bir yanıt üreten
    servisler (Redis/Docker API/Elasticsearch) için ortak akış.

    `build_response(payload)` ham baytları (ya da hiç yanıt yoksa None)
    döner - protokole özgü mantık tamamen saf, bağımsız test edilebilir
    fonksiyonlarda kalır; bu fonksiyon sadece I/O ve loglama akışını
    (`_handle_generic` ile aynı disiplin) sağlar."""
    source_ip, source_port = _peer_info(writer)

    if soar_enabled and _is_quarantined(source_ip):
        await _serve_quarantine(service_name, dest_port, reader, writer, source_ip,
                                source_port, respond=build_response)
        return

    if soar_enabled and _is_blocked(source_ip):
        storage.log_event(source_ip, service_name, "blocked", source_port=source_port,
                           dest_port=dest_port)
        logger.info("ENGELLENDI: %s -> %s (SOAR kisitlamasi aktif)", source_ip, service_name)
        await _close(writer)
        return

    storage.log_event(source_ip, service_name, "connect", source_port=source_port,
                       dest_port=dest_port)
    logger.info("baglanti: %s -> %s (port %s)", source_ip, service_name, dest_port)

    try:
        payload = await _read_payload(reader)
        if payload:
            storage.log_event(source_ip, service_name, "data", source_port=source_port,
                               dest_port=dest_port, payload=payload)
            _check_honeytokens(source_ip, payload)
        response = build_response(payload or "")
        if response:
            await _response_jitter()
            writer.write(response)
            await writer.drain()
    finally:
        storage.log_event(source_ip, service_name, "disconnect", source_port=source_port,
                           dest_port=dest_port)
        await _close(writer)

    _evaluate_and_log_alarm(source_ip, soar_enabled=soar_enabled)


def _make_bespoke_handler(service_name: str, dest_port: int, build_response,
                          soar_enabled: bool = False):
    async def handler(reader, writer):
        await _handle_bespoke_service(service_name, dest_port, reader, writer,
                                      soar_enabled, build_response)
    return handler


async def start_all_services(rotator=None, soar_enabled=False):
    """Config.FAKE_SERVICES icinde tanimli tum sahte servisleri baslatir ve
    sonsuza kadar (Ctrl+C ile durdurulana dek) calistirir.

    rotator verilirse (bkz. arachne/mtd/identity_rotator.py), servisler
    sabit banner yerine zaman icinde donen bir banner kullanir (Faz 4:
    Moving Target Defense) - varsayilan (rotator=None) davranis Faz 1-3
    ile birebir aynidir.

    soar_enabled=True verilirse (Faz 7), alarm uretildiginde otomatik
    mudahale playbook'lari calisir ve engellenen IP'lerin baglantilari
    gercekten reddedilir. Varsayilan KAPALIdir."""
    storage.init_db()
    servers = []
    for service_name, cfg in config.FAKE_SERVICES.items():
        port = cfg["port"]
        if service_name == "http-admin":
            handler = lambda r, w, p=port: _handle_http_admin(p, r, w,
                                                              soar_enabled=soar_enabled)
        elif service_name in _BESPOKE_RESPONSE_BUILDERS:
            handler = _make_bespoke_handler(service_name, port,
                                            _BESPOKE_RESPONSE_BUILDERS[service_name],
                                            soar_enabled=soar_enabled)
        else:
            handler = _make_generic_handler(service_name, port, rotator=rotator,
                                            soar_enabled=soar_enabled)
        server = await asyncio.start_server(handler, "0.0.0.0", port)
        servers.append(server)
        logger.info("%s honeypot dinlemede: 0.0.0.0:%s", service_name, port)

    try:
        await asyncio.gather(*(s.serve_forever() for s in servers))
    finally:
        for s in servers:
            s.close()
