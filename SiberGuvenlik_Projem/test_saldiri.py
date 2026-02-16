from scapy.all import IP, ICMP, send
import time

hedef_ip = "127.0.0.1" # Kendi bilgisayarın

print("[*] Test saldırısı başlatılıyor...")
for i in range(100):
    # Sahte bir ping paketi gönderiyoruz
    paket = IP(dst=hedef_ip)/ICMP()
    send(paket, verbose=False)
    if i % 10 == 0:
        print(f"[*] {i} paket gönderildi...")