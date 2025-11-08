# app.py
from flask import Flask, render_template_string, Response, request, abort
import os
import json
import re
from functools import wraps

app = Flask(__name__)

# Güvenlik ayarları
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
app.config['JSON_SORT_KEYS'] = False

# Rate limiting için basit bir decorator
from flask import g
import time

def rate_limit(requests_per_minute=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'last_request_time'):
                g.last_request_time = {}
            
            client_ip = request.remote_addr
            current_time = time.time()
            
            if client_ip in g.last_request_time:
                time_since_last_request = current_time - g.last_request_time[client_ip]
                if time_since_last_request < 60.0 / requests_per_minute:
                    abort(429)  # Too Many Requests
                    
            g.last_request_time[client_ip] = current_time
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Input validation fonksiyonu
def validate_input(text, max_length=100):
    if not text or len(text) > max_length:
        return False
    # Sadece harf, rakam, boşluk ve bazı özel karakterlere izin ver
    if not re.match(r'^[a-zA-Z0-9\s\.\-\_@]+$', text):
        return False
    return True

# SQL injection ve XSS koruması
def sanitize_input(text):
    if not text:
        return ""
    # HTML tag'lerini temizle
    clean = re.compile('<.*?>')
    text = re.sub(clean, '', text)
    # Tehlikeli karakterleri escape et
    text = text.replace('"', '&quot;').replace("'", '&#x27;')
    return text

# YENİ API LİSTESİ - Keneviz API
ALL_APIS = [
    # 🔹 YABANCI SORGULARI
    {"id": "yabanci", "title": "YABANCI SORGULAMA", "icon": "🌍",
     "url": "https://keneviz.api.trr.gt.tc/yabanci?ad=JOHN&soyad=DOE", "desc": "Yabancı ad soyad sorgulama."},

    # 🔹 TC DETAY SORGULARI
    {"id": "cinsiyet", "title": "CİNSİYET SORGULAMA", "icon": "⚧️",
     "url": "https://keneviz.api.trr.gt.tc/cinsiyet?tc=11111111111", "desc": "TC ile cinsiyet sorgulama."},
    {"id": "din", "title": "DİN SORGULAMA", "icon": "🕌",
     "url": "https://keneviz.api.trr.gt.tc/din?tc=11111111111", "desc": "TC ile din bilgisi sorgulama."},
    {"id": "vergino_tc", "title": "VERGİ NO SORGULAMA", "icon": "💰",
     "url": "https://keneviz.api.trr.gt.tc/vergino?tc=11111111111", "desc": "TC ile vergi numarası sorgulama."},
    {"id": "medenihal", "title": "MEDENİ HAL SORGULAMA", "icon": "💍",
     "url": "https://keneviz.api.trr.gt.tc/medenihal?tc=11111111111", "desc": "TC ile medeni hal sorgulama."},
    {"id": "koy", "title": "KÖY SORGULAMA", "icon": "🏞️",
     "url": "https://keneviz.api.trr.gt.tc/koy?tc=11111111111", "desc": "TC ile köy bilgisi sorgulama."},
    {"id": "burc", "title": "BURÇ SORGULAMA", "icon": "♈",
     "url": "https://keneviz.api.trr.gt.tc/burc?tc=11111111111", "desc": "TC ile burç sorgulama."},
    {"id": "kimlikkayit", "title": "KİMLİK KAYIT SORGULAMA", "icon": "📋",
     "url": "https://keneviz.api.trr.gt.tc/kimlikkayit?tc=11111111111", "desc": "TC ile kimlik kayıt sorgulama."},
    {"id": "dogumyeri", "title": "DOĞUM YERİ SORGULAMA", "icon": "🏥",
     "url": "https://keneviz.api.trr.gt.tc/dogumyeri?tc=11111111111", "desc": "TC ile doğum yeri sorgulama."},

    # 🔹 YETİMLİK SORGUSU
    {"id": "yetimlik", "title": "YETİMLİK SORGULAMA", "icon": "👨‍👧‍👦",
     "url": "https://keneviz.api.trr.gt.tc/yetimlik?babatc=11111111111", "desc": "Baba TC ile yetimlik sorgulama."},

    # 🔹 AİLE SORGULARI
    {"id": "kardes", "title": "KARDEŞ SORGULAMA", "icon": "👥",
     "url": "https://keneviz.api.trr.gt.tc/kardes?tc=11111111111", "desc": "TC ile kardeş bilgisi sorgulama."},
    {"id": "anne", "title": "ANNE SORGULAMA", "icon": "👩",
     "url": "https://keneviz.api.trr.gt.tc/anne?tc=11111111111", "desc": "TC ile anne bilgisi sorgulama."},
    {"id": "baba", "title": "BABA SORGULAMA", "icon": "👨",
     "url": "https://keneviz.api.trr.gt.tc/baba?tc=11111111111", "desc": "TC ile baba bilgisi sorgulama."},
    {"id": "cocuklar", "title": "ÇOCUKLAR SORGULAMA", "icon": "👶",
     "url": "https://keneviz.api.trr.gt.tc/cocuklar?tc=11111111111", "desc": "TC ile çocuk bilgisi sorgulama."},
    {"id": "amca", "title": "AMCA SORGULAMA", "icon": "👨‍🦳",
     "url": "https://keneviz.api.trr.gt.tc/amca?tc=11111111111", "desc": "TC ile amca bilgisi sorgulama."},
    {"id": "dayi", "title": "DAYI SORGULAMA", "icon": "👨‍🦱",
     "url": "https://keneviz.api.trr.gt.tc/dayi?tc=11111111111", "desc": "TC ile dayı bilgisi sorgulama."},
    {"id": "hala", "title": "HALA SORGULAMA", "icon": "👩‍🦳",
     "url": "https://keneviz.api.trr.gt.tc/hala?tc=11111111111", "desc": "TC ile hala bilgisi sorgulama."},
    {"id": "teyze", "title": "TEYZE SORGULAMA", "icon": "👩‍🦱",
     "url": "https://keneviz.api.trr.gt.tc/teyze?tc=11111111111", "desc": "TC ile teyze bilgisi sorgulama."},
    {"id": "kuzen", "title": "KUZEN SORGULAMA", "icon": "🧑‍🤝‍🧑",
     "url": "https://keneviz.api.trr.gt.tc/kuzen?tc=11111111111", "desc": "TC ile kuzen bilgisi sorgulama."},
    {"id": "dede", "title": "DEDE SORGULAMA", "icon": "👴",
     "url": "https://keneviz.api.trr.gt.tc/dede?tc=11111111111", "desc": "TC ile dede bilgisi sorgulama."},
    {"id": "nine", "title": "NİNE SORGULAMA", "icon": "👵",
     "url": "https://keneviz.api.trr.gt.tc/nine?tc=11111111111", "desc": "TC ile nine bilgisi sorgulama."},
    {"id": "yeniden", "title": "YENİDEN SORGULAMA", "icon": "🔄",
     "url": "https://keneviz.api.trr.gt.tc/yeniden?tc=11111111111", "desc": "TC ile yeniden sorgulama."},

    # 🔹 SAHMARAN BOTU SORGULARI
    {"id": "sorgu", "title": "AD SOYAD SORGULAMA", "icon": "🔍",
     "url": "https://keneviz.api.trr.gt.tc/sorgu?ad=AHMET&soyad=YILMAZ", "desc": "Ad soyad ile kişi sorgulama."},
    {"id": "aile_sahmaran", "title": "AILE SORGULAMA", "icon": "🏠",
     "url": "https://keneviz.api.trr.gt.tc/aile?tc=11111111111", "desc": "TC ile aile bilgisi sorgulama."},
    {"id": "adres_sahmaran", "title": "ADRES SORGULAMA", "icon": "📍",
     "url": "https://keneviz.api.trr.gt.tc/adres?tc=11111111111", "desc": "TC ile adres sorgulama."},
    {"id": "tc_sahmaran", "title": "TC SORGULAMA", "icon": "🆔",
     "url": "https://keneviz.api.trr.gt.tc/tc?tc=11111111111", "desc": "TC kimlik sorgulama."},
    {"id": "gsmtc", "title": "GSM TC SORGULAMA", "icon": "📱",
     "url": "https://keneviz.api.trr.gt.tc/gsmtc?gsm=5551112233", "desc": "GSM numarası ile TC sorgulama."},
    {"id": "tcgsm", "title": "TC GSM SORGULAMA", "icon": "📞",
     "url": "https://keneviz.api.trr.gt.tc/tcgsm?tc=11111111111", "desc": "TC ile GSM numarası sorgulama."},
    {"id": "olumtarihi", "title": "ÖLÜM TARİHİ SORGULAMA", "icon": "⚰️",
     "url": "https://keneviz.api.trr.gt.tc/olumtarihi?tc=11111111111", "desc": "TC ile ölüm tarihi sorgulama."},
    {"id": "sulale", "title": "SÜLALE SORGULAMA", "icon": "🌳",
     "url": "https://keneviz.api.trr.gt.tc/sulale?tc=11111111111", "desc": "TC ile sülale sorgulama."},
    {"id": "sms", "title": "SMS SORGULAMA", "icon": "💬",
     "url": "https://keneviz.api.trr.gt.tc/sms?gsm=5551112233", "desc": "GSM ile SMS sorgulama."},
    {"id": "kizliksoyad", "title": "KIZLIK SOYADI SORGULAMA", "icon": "👰",
     "url": "https://keneviz.api.trr.gt.tc/kizliksoyad?tc=11111111111", "desc": "TC ile kızlık soyadı sorgulama."},
    {"id": "yas_sahmaran", "title": "YAŞ SORGULAMA", "icon": "🎂",
     "url": "https://keneviz.api.trr.gt.tc/yas?tc=11111111111", "desc": "TC ile yaş sorgulama."},
    {"id": "hikaye", "title": "HAYAT HİKAYESİ SORGULAMA", "icon": "📖",
     "url": "https://keneviz.api.trr.gt.tc/hikaye?tc=11111111111", "desc": "TC ile hayat hikayesi sorgulama."},
    {"id": "sirano", "title": "SIRA NO SORGULAMA", "icon": "🔢",
     "url": "https://keneviz.api.trr.gt.tc/sirano?tc=11111111111", "desc": "TC ile sıra no sorgulama."},
    {"id": "ayakno", "title": "AYAK NO SORGULAMA", "icon": "👣",
     "url": "https://keneviz.api.trr.gt.tc/ayakno?tc=11111111111", "desc": "TC ile ayak no sorgulama."},
    {"id": "operator", "title": "OPERATÖR SORGULAMA", "icon": "📶",
     "url": "https://keneviz.api.trr.gt.tc/operator?gsm=5551112233", "desc": "GSM ile operatör sorgulama."},
    {"id": "yegen", "title": "YEĞEN SORGULAMA", "icon": "🧒",
     "url": "https://keneviz.api.trr.gt.tc/yegen?tc=11111111111", "desc": "TC ile yeğen bilgisi sorgulama."},
    {"id": "cocuk", "title": "ÇOCUK SORGULAMA", "icon": "👧",
     "url": "https://keneviz.api.trr.gt.tc/cocuk?tc=11111111111", "desc": "TC ile çocuk bilgisi sorgulama."},

    # 🔹 MİYAVREM BOTU SORGULARI
    {"id": "vesika", "title": "VESİKA SORGULAMA", "icon": "🪪",
     "url": "https://keneviz.api.trr.gt.tc/vesika?tc=11111111111", "desc": "TC ile vesika sorgulama."},
    {"id": "plaka", "title": "PLAKA SORGULAMA", "icon": "🚗",
     "url": "https://keneviz.api.trr.gt.tc/plaka?plaka=34ABC123", "desc": "Plaka ile araç sorgulama."},
    {"id": "tcplaka", "title": "TC PLAKA SORGULAMA", "icon": "🚙",
     "url": "https://keneviz.api.trr.gt.tc/tcplaka?tc=11111111111", "desc": "TC ile plaka sorgulama."}
]

# HTML template (Güvenlik header'ları eklendi, API URL'leri gizlendi)
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; img-src 'self' data: https:;">
<meta name="referrer" content="no-referrer">
<title>Keneviz API Servisi — v1</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--bg-1:#0f1724;--bg-2:#0b1220;--accent-1:#4cc9f0;--accent-2:#ff8a00;--glass:rgba(255,255,255,0.06);--card-border:rgba(255,255,255,0.06);--muted:#cbd5e1;--glass-blur:10px;--radius:14px}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,system-ui,Arial;background:radial-gradient(1200px 600px at 10% 10%, rgba(76,201,240,0.06), transparent), linear-gradient(135deg,var(--bg-1) 0%,var(--bg-2) 100%);color:#fff;min-height:100vh;padding:16px;position:relative}
.bg-image{position:fixed;inset:0;background-image:url('https://i.ibb.co/d0drWBr0/MG-20251108-140110-475.jpg');background-size:cover;background-position:center;opacity:0.55;z-index:-3;filter:grayscale(10%);transition:filter .35s ease, opacity .35s ease}
.bg-image.blurred{filter:blur(6px) saturate(0.75);opacity:0.46}
.gradient-overlay{position:fixed;inset:0;z-index:-2;background:linear-gradient(90deg, rgba(255,140,0,0.06), rgba(76,201,240,0.04));mix-blend-mode:overlay;pointer-events:none}
.wrapper{max-width:1200px;margin:0 auto}
.header-top{display:flex;justify-content:space-between;align-items:center;gap:12px}
.controls{display:flex;gap:10px;align-items:center}
.search{display:flex;align-items:center;background:var(--glass);padding:8px 12px;border-radius:12px;border:1px solid var(--card-border);gap:8px;flex:1;min-width:200px;max-width:400px}
.search input{background:transparent;border:0;outline:0;color:inherit;font-size:14px;width:100%}
.api-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-top:12px}
.api-card{background:var(--glass);padding:14px;border-radius:var(--radius);border:1px solid var(--card-border);backdrop-filter:blur(var(--glass-blur));display:flex;flex-direction:column;gap:10px}
.api-head{display:flex;align-items:flex-start;gap:10px}
.api-icon{width:42px;height:42px;border-radius:8px;display:grid;place-items:center;font-size:18px;background:linear-gradient(135deg,#4361ee,#3a0ca3)}
.api-title{font-weight:700;color:#ff6aa2;font-size:14px;cursor:pointer}
.api-desc{font-size:12px;color:var(--muted)}
.api-url{display:none} /* API URL'leri gizlendi */
.card-actions{display:flex;gap:6px;flex-wrap:wrap}
.btn{padding:6px 8px;border-radius:8px;border:1px solid var(--card-border);background:transparent;color:#fff;cursor:pointer}
.badge{padding:4px 8px;border-radius:999px;background:rgba(40,167,69,0.18);color:#b7f0c1;font-weight:700;font-size:11px}
.toast{position:fixed;right:12px;bottom:12px;background:#0b1220;padding:8px 12px;border-radius:8px;border:1px solid var(--card-border);display:none;z-index:50;font-size:13px}
.security-note{background:rgba(255,180,180,0.1);border:1px solid rgba(255,180,180,0.3);padding:8px 12px;border-radius:8px;margin:10px 0;font-size:12px}
@media (max-width:768px){.api-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="bg-image" id="bgImage"></div>
<div class="gradient-overlay"></div>
<div class="wrapper">
  <header>
    <div class="header-top">
      <div>
        <h1>Keneviz System</h1>
        <div style="color:var(--muted);font-size:13px">Secure API Service • Mobile Uyumlu</div>
      </div>
      <div class="controls">
        <div style="margin-right:8px"><strong>{{ total }}</strong> API</div>
      </div>
    </div>

    <div style="display:flex;gap:8px;margin-top:10px;align-items:center">
      <div class="search"><i class="fa fa-search" style="opacity:0.7;margin-right:8px"></i><input id="q" placeholder="API ara..." onkeyup="searchApis()" /></div>
      <button class="btn" onclick="toggleBackground()">BG</button>
      <button class="btn" onclick="downloadAll()"><i class="fa fa-download"></i> Tüm API'leri JSON indir</button>
    </div>
  </header>

  <main>
    <div class="security-note">
      <i class="fa fa-shield-alt" style="color:#ffb4b4;margin-right:8px"></i>
      <strong>Güvenlik Önlemi:</strong> API URL'leri gizlenmiştir. Kopyala butonu ile güvenli şekilde URL'leri alabilirsiniz.
    </div>

    <h2 style="color:var(--accent-1);margin-bottom:8px">🚀 KENEVİZ API LİSTESİ ({{ total }} API)</h2>

    <div class="api-grid" id="allApisGrid">
      {% for api in apis %}
      <div class="api-card" data-text="{{ (api.id ~ ' ' ~ api.title ~ ' ' ~ api.desc ~ ' ' ~ api.url)|lower|e }}" data-url="{{ api.url|e }}">
        <div class="api-head">
          <div class="api-icon">{{ api.icon }}</div>
          <div style="flex:1">
            <div class="api-title" onclick="copyToClipboard(this.closest('.api-card').dataset.url)">{{ api.title }}</div>
            <div class="api-desc">{{ api.desc }}</div>
          </div>
          <div style="display:flex;align-items:center;gap:8px"><div class="badge">Aktif</div></div>
        </div>

        <div class="card-actions">
          <button class="btn" onclick="copyToClipboard(this.closest('.api-card').dataset.url)"><i class="fa fa-copy"></i> URL'yi Kopyala</button>
          <button class="btn" onclick="openUrl(this.closest('.api-card').dataset.url)"><i class="fa fa-arrow-up-right-from-square"></i> API'yi Aç</button>
        </div>
      </div>
      {% endfor %}
    </div>
  </main>

  <footer style="margin-top:20px;text-align:center;color:var(--muted);font-size:12px">
    KENEVİZ SYSTEM SUNAR — v1 • {{ total }} API • Secure • Mobile Uyumlu<br>© 2025 Keneviz System • Telegram: @sukazatkinis
  </footer>
</div>

<div class="toast" id="toast">Kopyalandı!</div>

<script>
function searchApis(){
  const q=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('[data-text]').forEach(el=>el.style.display = el.dataset.text.includes(q) ? '' : 'none');
}
async function copyToClipboard(text){
  if(!text) return showToast('Kopyalanacak metin yok');
  try{
    if(navigator.clipboard && navigator.clipboard.writeText){ await navigator.clipboard.writeText(text); }
    else { const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.left='-9999px'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }
    showToast('API URL kopyalandı!');
  }catch(e){ console.error(e); showToast('Kopyalama başarısız'); }
}
function openUrl(url){
  if(!url) return showToast('Açılacak adres yok');
  try{ window.open(url,'_blank'); }catch(e){
    const a=document.createElement('a'); a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(url); a.target='_blank'; document.body.appendChild(a); a.click(); a.remove();
  }
}
async function downloadAll(){
  try{
    const resp=await fetch('/api-list'); if(!resp.ok) throw new Error('İndirilemedi');
    const blob=await resp.blob(); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='keneviz-apis.json'; document.body.appendChild(a); a.click(); URL.revokeObjectURL(a.href); a.remove();
    showToast('keneviz-apis.json indiriliyor...');
  }catch(e){ console.error(e); showToast('İndirme başarısız'); }
}
function toggleBackground(){ document.getElementById('bgImage').classList.toggle('blurred'); }
function showToast(msg){ const t=document.getElementById('toast'); t.innerText=msg; t.style.display='block'; clearTimeout(window._toastTimer); window._toastTimer=setTimeout(()=>{ t.style.display='none'; },1500); }
</script>
</body>
</html>
"""

# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template_string('<h1>404 - Sayfa Bulunamadı</h1><p>İstediğiniz sayfa mevcut değil.</p>'), 404

@app.errorhandler(429)
def too_many_requests(error):
    return render_template_string('<h1>429 - Çok Fazla İstek</h1><p>Lütfen daha yavaş istek gönderin.</p>'), 429

@app.errorhandler(500)
def internal_error(error):
    return render_template_string('<h1>500 - Sunucu Hatası</h1><p>Bir şeyler yanlış gitti.</p>'), 500

# Routes
@app.route("/")
@rate_limit(requests_per_minute=30)
def home():
    return render_template_string(HTML_TEMPLATE, apis=ALL_APIS, total=len(ALL_APIS))

@app.route("/api-list")
@rate_limit(requests_per_minute=10)
def api_list():
    return Response(json.dumps({"total": len(ALL_APIS), "apis": ALL_APIS}, ensure_ascii=False, indent=2),
                    content_type="application/json; charset=utf-8")

# Health check endpoint
@app.route("/health")
def health_check():
    return {"status": "healthy", "total_apis": len(ALL_APIS)}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
