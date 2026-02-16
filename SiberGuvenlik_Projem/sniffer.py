from scapy.all import sniff, Raw, IP
from datetime import datetime
import time

# --- AYARLAR ---
LOG_FILE = "guvenlik_kayitlari.txt"
DOS_ESIK_DEGERI = 50  # Saniyede 50 paket
ip_stats = {}         # IP trafiğini takip etmek için: {ip: [sayac, son_zaman]}

def detect_dos(src_ip):
    """Zaman bazlı DoS saldırı tespiti yapar."""
    current_time = time.time()
    
    if src_ip not in ip_stats:
        ip_stats[src_ip] = [1, current_time]
    else:
        # Eğer son paketin üzerinden 1 saniyeden fazla geçtiyse sayacı sıfırla
        if current_time - ip_stats[src_ip][1] > 1:
            ip_stats[src_ip] = [1, current_time]
        else:
            ip_stats[src_ip][0] += 1
            
    # Eğer aynı saniye içinde eşik değeri aşılırsa uyarı ver
    if ip_stats[src_ip][0] > DOS_ESIK_DEGERI:
        return True
    return False

def packet_callback(packet):
    """Her paket yakalandığında çalışan ana fonksiyon."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # 1. DoS Kontrolü
        if detect_dos(src_ip):
            uyari_msg = f"[!!!] KRİTİK: {src_ip} adresinden DoS saldırısı şüphesi!"
            print(uyari_msg)
            save_log(uyari_msg)

        # 2. İçerik Analizi (HTTP/DNS/Hassas Veri)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                # Veriyi decode et (Hata alırsan görmezden gel)
                decoded_payload = payload.decode('utf-8', errors='ignore').lower()
                
                # Aranan şüpheli anahtar kelimeler
                targets = ["user", "pass", "login", "admin", "config", "select", "union"]
                
                if any(word in decoded_payload for word in targets):
                    zaman = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = f"[{zaman}] HASSAS VERİ: {src_ip} -> {dst_ip} | İÇERİK: {decoded_payload[:80]}"
                    
                    print(f"\n[!] TESPİT EDİLDİ: {log_entry}")
                    save_log(log_entry)
            except:
                pass

def save_log(message):
    """Tespit edilen olayları dosyaya kaydeder."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

# --- BAŞLATICI ---
print("-" * 50)
print("   SENTINEL-NET SİBER GÜVENLİK ANALİZ ARACI   ")
print(f"[*] Kayıt dosyası: {LOG_FILE}")
print("[*] Dinleme başlatıldı... Durdurmak için Ctrl+C")
print("-" * 50)

# Sniffer'ı başlat
sniff(prn=packet_callback, store=0)