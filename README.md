# 🔍 Python ile Temel Ağ Zafiyet Tarayıcı

## ⚠️ Yasal Uyarı

Bu araç tamamen **eğitim, siber güvenlik testleri ve ağ yönetimi** amaçlı geliştirilmiştir. 
* Yetkiniz olmayan ağlar üzerinde tarama yapmak etik dışıdır ve yasal sorumluluk doğurabilir. 
* Bu aracın kullanımından doğabilecek tüm sorumluluk tamamen kullanıcıya aittir.

Bu proje, yerel ağdaki veya belirli bir IP aralığındaki (CIDR) açık portları tespit eden, servisleri tanımlayan ve yaygın güvenlik riskleri hakkında çözüm odaklı ipuçları üreten **eğitim amaçlı** bir siber güvenlik aracıdır.

## ✨ Öne Çıkan Özellikler

* **Esnek Hedefleme:** Tekil IP veya CIDR (örneğin: `192.168.1.0/24`) aralığında geniş kapsamlı tarama yapabilir.
* **Hibrit Tarama Modu:** * Sistemde `nmap` mevcutsa gelişmiş servis tespiti (versiyon bilgisi vb.) yapar.
    * Nmap yüklü değilse, saf Python **soket tabanlı** tarama yöntemine otomatik olarak geçiş yapar.
* **Yüksek Performans:** `ThreadPoolExecutor` (Multithreading) mimarisi sayesinde yüzlerce portu ve hostu eşzamanlı olarak tarar.
* **Risk Analizi:** Tespit edilen kritik portlar (FTP, Telnet, RDP vb.) için güncel güvenlik tavsiyeleri sunar.
* **Ayrıntılı Raporlama:** Host durumu, açık portlar, servis isimleri ve banner bilgilerini içeren okunabilir raporlar üretir.

## 🛠️ Kullanılan Teknolojiler

* **Dil:** Python 3.x
* **Ağ Programlama:** `socket`, `ipaddress`
* **Eşzamanlılık (Concurrency):** `concurrent.futures` (Multithreading)
* **Opsiyonel Kütüphaneler:** `python-nmap` (Gelişmiş tarama için)
* **CLI Yönetimi:** `argparse`

## 🚀 Kurulum

1.  **Depoyu klonlayın:**
    ```bash
    git clone [https://github.com/KULLANICI_ADIN/depo_adi.git](https://github.com/KULLANICI_ADIN/depo_adi.git)
    ```
2.  **(Opsiyonel) Nmap desteği için kütüphaneyi yükleyin:**
    ```bash
    pip install python-nmap
    ```
    *Not: Gelişmiş mod için sisteminizde Nmap'in kurulu ve PATH'e ekli olması gerekmektedir.*

## 📖 Kullanım Örnekleri

### 1. Temel Taramalar
```bash
# Tek bir IP adresini tarar
python "Python ile Ağ Zafiyet Tarayıcı.py" 192.168.1.10

# Tüm ağ aralığını (CIDR) tarar
python "Python ile Ağ Zafiyet Tarayıcı.py" 192.168.1.0/24

# Belirli portları veya port aralığını tarar
python "Python ile Ağ Zafiyet Tarayıcı.py" 192.168.1.10 --ports 22,80,443,1-1024

# Mevcutsa Nmap motoru ile servis tespiti yapar
python "Python ile Ağ Zafiyet Tarayıcı.py" 192.168.1.0/24 --use-nmap

# Zaman aşımı (timeout) süresini belirler (varsayılan 0.5s)
python "Python ile Ağ Zafiyet Tarayıcı.py" 192.168.1.0/24 --timeout 1.0

---

## ⚡ Performans İpuçları

Tarama sürecini ağ yapınıza göre optimize etmek için aşağıdaki parametreleri kullanabilirsiniz:

* **Hız İçin:** `--workers` değerini artırın (Genellikle **200-400** arası önerilir). Bu, aynı anda taranan hedef ve port sayısını artırır.
* **Doğruluk İçin:** Eğer tarama yaptığınız ağ hızı düşükse veya paket kayıpları yaşanıyorsa, `--timeout` değerini yükseltmeniz (Örn: `1.0`) açık portların gözden kaçmasını engeller.
* **Odaklanma:** Toplam tarama süresini kısaltmak için `--ports` parametresini kullanarak sadece hedeflediğiniz (Örn: `80,443,22`) portları belirtin.

## ⚠️ Yasal Uyarı

Bu araç tamamen **eğitim, siber güvenlik testleri ve ağ yönetimi** amaçlı geliştirilmiştir. 
* Yetkiniz olmayan ağlar üzerinde tarama yapmak etik dışıdır ve yasal sorumluluk doğurabilir. 
* Bu aracın kullanımından doğabilecek tüm sorumluluk tamamen kullanıcıya aittir.

---
