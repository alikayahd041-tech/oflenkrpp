import os
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from authlib.integrations.flask_client import OAuth
from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

ROOT_OWNER_EMAIL = "alikayahd041@gmail.com"

ROLES = [
    "Project Manager", "Deputy Project Manager", "Project Coordinator",
    "Chief Administrator", "Deputy Chief Administrator", "Senior Administrator",
    "Junior Administrator", "Server Administrator", "Admin Assistant"
]

ROLE_LEVEL = {
    "Admin Assistant": 10,
    "Server Administrator": 20,
    "Junior Administrator": 30,
    "Senior Administrator": 40,
    "Deputy Chief Administrator": 50,
    "Chief Administrator": 60,
    "Project Coordinator": 70,
    "Deputy Project Manager": 80,
    "Project Manager": 90,
    "ROOT_OWNER": 1000
}

SERVERS = {
    "tr": {
        "name": "TR Sunucusu", "lang": "tr", "dir": "ltr",
        "rules": ["Genel Kurallar", "Devlet Kuralları", "Liderlik Kuralları", "Yeşil Bölge Kuralları"],
        "government": ["Hastane", "Ordu", "Şehir Polisi", "FBI", "Medya", "Belediye"],
        "getto": ["Fangs", "Wolves", "Rawens"]
    },
    "ksa": {
        "name": "خادم KSA", "lang": "ar", "dir": "rtl",
        "rules": ["القوانين العامة", "قوانين الدولة", "قوانين القيادة", "قوانين المنطقة الخضراء"],
        "government": ["المستشفى", "الجيش", "شرطة المدينة", "FBI", "الإعلام", "البلدية"],
        "getto": ["Fangs", "Wolves", "Rawens"]
    }
}

TEXT = {
"tr": {
    "home":"Ana Sayfa","login":"Google ile Giriş","logout":"Çıkış",
    "complaints":"Şikayetler","applications":"Başvurular","rules":"Kurallar",
    "government":"Devlet Kurumları","getto":"Getto","companies":"Şirketler",
    "admin":"Yönetim Paneli","new_complaint":"Şikayet Gönder",
    "player_complaint":"Oyuncu Şikayeti","admin_complaint":"Yönetici Şikayeti",
    "leader":"Liderlik Başvurusu","manager":"Yönetici Başvurusu","assistant":"Asistan Başvurusu",
    "save":"Kaydet","status":"Durum","back":"Geri"
},
"ksa": {
    "home":"الرئيسية","login":"تسجيل الدخول عبر Google","logout":"تسجيل الخروج",
    "complaints":"الشكاوى","applications":"الطلبات","rules":"القوانين",
    "government":"مؤسسات الدولة","getto":"العصابات","companies":"الشركات",
    "admin":"لوحة الإدارة","new_complaint":"إرسال شكوى",
    "player_complaint":"شكوى لاعب","admin_complaint":"شكوى ضد إداري",
    "leader":"طلب القيادة","manager":"طلب الإدارة","assistant":"طلب المساعد",
    "save":"حفظ","status":"الحالة","back":"رجوع"
}}

def db_required():
    if not supabase:
        abort(500, "Supabase environment variables are missing.")

def current_user():
    return session.get("user")

def root_owner():
    u = current_user()
    return bool(u and u.get("email","").lower() == ROOT_OWNER_EMAIL.lower())

def user_role():
    u = current_user()
    if not u: return None
    if root_owner(): return "ROOT_OWNER"
    try:
        r = supabase.table("user_roles").select("role").eq("user_id", u["id"]).execute()
        return r.data[0]["role"] if r.data else None
    except Exception:
        return None

def admin_required(min_role="Admin Assistant"):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not current_user(): return redirect(url_for("login"))
            role = user_role()
            if not role or ROLE_LEVEL.get(role,0) < ROLE_LEVEL[min_role]:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

def owner_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not root_owner(): abort(403)
        return fn(*args, **kwargs)
    return wrapped

@app.context_processor
def inject():
    sid = request.view_args.get("server") if request.view_args else None
    if sid not in SERVERS: sid = session.get("server", "tr")
    session["server"] = sid
    return {
        "user": current_user(),
        "role": user_role(),
        "is_owner": root_owner(),
        "server": sid,
        "server_data": SERVERS[sid],
        "t": TEXT[SERVERS[sid]["lang"]]
    }

@app.route("/")
def index():
    return render_template("index.html", servers=SERVERS)

@app.route("/server/<server>")
def dashboard(server):
    if server not in SERVERS: abort(404)
    session["server"] = server
    return render_template("dashboard.html")

# ---------- Google OAuth ----------
oauth = OAuth(app)
if os.environ.get("GOOGLE_CLIENT_ID"):
    google = oauth.register(
        name="google", client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope":"openid email profile"}
    )

@app.route("/login")
def login():
    if not os.environ.get("GOOGLE_CLIENT_ID"): return render_template("setup.html")
    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/callback")
def auth_callback():
    token = oauth.google.authorize_access_token()
    info = token.get("userinfo")
    if not info: abort(401)
    db_required()
    existing = supabase.table("profiles").select("*").eq("email", info["email"]).execute()
    if existing.data:
        profile = existing.data[0]
        supabase.table("profiles").update({
            "name": info.get("name"), "avatar_url": info.get("picture")
        }).eq("id", profile["id"]).execute()
    else:
        profile = supabase.table("profiles").insert({
            "email": info["email"], "name": info.get("name"), "avatar_url": info.get("picture")
        }).execute().data[0]
    session["user"] = {"id": profile["id"], "email": profile["email"], "name": profile["name"], "avatar_url": profile.get("avatar_url")}
    return redirect(url_for("dashboard", server=session.get("server","tr")))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------- Rules ----------
@app.route("/server/<server>/rules")
def rules(server):
    if server not in SERVERS: abort(404)
    session["server"] = server
    q = supabase.table("rules").select("*").eq("server", server).order("sort_order").execute()
    return render_template("rules.html", rows=q.data)

@app.route("/server/<server>/rules/new", methods=["GET","POST"])
@admin_required("Junior Administrator")
def new_rule(server):
    if server not in SERVERS: abort(404)
    if request.method == "POST":
        supabase.table("rules").insert({
            "server": server, "category": request.form["category"],
            "title": request.form["title"], "body": request.form["body"],
            "sort_order": int(request.form.get("sort_order") or 0),
            "author_id": current_user()["id"]
        }).execute()
        flash("Kural kaydedildi.")
        return redirect(url_for("rules", server=server))
    return render_template("rule_form.html", categories=SERVERS[server]["rules"])

# ---------- Complaints ----------
@app.route("/server/<server>/complaints")
def complaints(server):
    if server not in SERVERS: abort(404)
    session["server"] = server
    q = supabase.table("complaints").select("*").eq("server", server).order("created_at", desc=True).execute()
    return render_template("complaints.html", rows=q.data)

@app.route("/server/<server>/complaints/new/<kind>", methods=["GET","POST"])
def new_complaint(server, kind):
    if server not in SERVERS or kind not in ("player","admin"): abort(404)
    if not current_user(): return redirect(url_for("login"))
    if request.method == "POST":
        supabase.table("complaints").insert({
            "server": server, "kind": kind, "crime": request.form["crime"],
            "reported_name": request.form["reported_name"],
            "nickname": request.form["nickname"], "static_id": request.form["static_id"],
            "admin_nickname": request.form.get("admin_nickname"),
            "date_text": request.form["date_text"], "time_text": request.form["time_text"],
            "proof": request.form["proof"], "submitted_by": current_user()["id"]
        }).execute()
        admins = supabase.table("profiles").select("id").execute()
        for a in admins.data:
            supabase.table("notifications").insert({
                "user_id": a["id"], "server": server,
                "message": "Yeni şikayet gönderildi.", "link": url_for("complaints", server=server)
            }).execute()
        flash("Şikayet gönderildi.")
        return redirect(url_for("complaints", server=server))
    return render_template("complaint_form.html", kind=kind)

@app.route("/server/<server>/complaints/<int:item_id>/status", methods=["POST"])
@admin_required("Admin Assistant")
def complaint_status(server, item_id):
    status = request.form["status"]
    supabase.table("complaints").update({
        "status": status, "decision_note": request.form.get("decision_note"),
        "reviewed_by": current_user()["id"], "reviewed_at": datetime.utcnow().isoformat()
    }).eq("id", item_id).eq("server", server).execute()
    return redirect(url_for("complaints", server=server))

# ---------- Applications ----------
APPLICATION_FIELDS = {
"leader": ["Gerçek adınız","Yaşınız","Saat diliminiz","Günlük ortalama aktiflik süreniz","Discord kullanıcı adınız","Oyun içi isminiz","Kalıcı oyuncu ID’niz","Liderlik başvurusu yapılan organizasyon","Neden özellikle bu organizasyonun lideri olmak istiyorsunuz?","Organizasyondaki RolePlay’i geliştirmek için önerileriniz nelerdir?"],
"manager": ["Gerçek adınız","Yaşınız","Saat diliminiz","Sunucu saatine göre aktif saatleriniz","Günlük ortalama aktiflik süreniz","Discord kullanıcı adınız","Oyun içi isminiz","Oyuncu ID’niz","Hangi bölümün küratörü olmak istiyorsunuz?","Neden yönetici olmak istiyorsunuz?","Güçlü yönleriniz","En büyük zayıf yönleriniz","RP hayatından çıkıp sadece yönetici olmaya hazır mısınız?","Şu anda aktif olmanızı engelleyen gerçek hayata dair bir probleminiz var mı?"],
"assistant": ["Gerçek adınız","Yaşınız","Saat diliminiz","Sunucu saatine göre aktif saatleriniz","Günlük ortalama aktiflik süreniz","Discord kullanıcı adınız","Oyun içi isminiz","Oyuncu ID’niz","Neden asistan olmak istiyorsunuz?","Güçlü yönleriniz","En büyük zayıf yönleriniz","Şu anda aktif olmanızı engelleyen gerçek hayata dair bir probleminiz var mı?"]
}

@app.route("/server/<server>/applications")
def applications(server):
    if server not in SERVERS: abort(404)
    session["server"] = server
    q = supabase.table("applications").select("*").eq("server", server).order("created_at", desc=True).execute()
    return render_template("applications.html", rows=q.data)

@app.route("/server/<server>/applications/new/<kind>", methods=["GET","POST"])
def new_application(server, kind):
    if server not in SERVERS or kind not in APPLICATION_FIELDS: abort(404)
    if not current_user(): return redirect(url_for("login"))
    if request.method == "POST":
        answers = {str(i+1): request.form.get(f"q{i+1}","") for i in range(len(APPLICATION_FIELDS[kind]))}
        supabase.table("applications").insert({
            "server":server,"kind":kind,"answers":answers,"submitted_by":current_user()["id"]
        }).execute()
        flash("Başvuru gönderildi.")
        return redirect(url_for("applications", server=server))
    return render_template("application_form.html", kind=kind, fields=APPLICATION_FIELDS[kind])

@app.route("/server/<server>/applications/<int:item_id>/status", methods=["POST"])
@admin_required("Admin Assistant")
def application_status(server, item_id):
    supabase.table("applications").update({
        "status":request.form["status"], "decision_note":request.form.get("decision_note"),
        "reviewed_by":current_user()["id"], "reviewed_at":datetime.utcnow().isoformat()
    }).eq("id",item_id).eq("server",server).execute()
    return redirect(url_for("applications",server=server))

# ---------- Government / Getto / Companies ----------
@app.route("/server/<server>/government")
def government(server):
    if server not in SERVERS: abort(404)
    return render_template("organizations.html", title=TEXT[SERVERS[server]["lang"]]["government"], items=SERVERS[server]["government"])

@app.route("/server/<server>/getto")
def getto(server):
    if server not in SERVERS: abort(404)
    return render_template("organizations.html", title=TEXT[SERVERS[server]["lang"]]["getto"], items=SERVERS[server]["getto"])

@app.route("/server/<server>/companies")
def companies(server):
    if server not in SERVERS: abort(404)
    q = supabase.table("companies").select("*").eq("server",server).order("name").execute()
    return render_template("companies.html", rows=q.data)

@app.route("/server/<server>/companies/new", methods=["GET","POST"])
@admin_required("Junior Administrator")
def new_company(server):
    if request.method=="POST":
        supabase.table("companies").insert({
            "server":server,"name":request.form["name"],"description":request.form["description"]
        }).execute()
        return redirect(url_for("companies",server=server))
    return render_template("company_form.html")

# ---------- Notifications ----------
@app.route("/notifications")
def notifications():
    if not current_user(): return redirect(url_for("login"))
    q = supabase.table("notifications").select("*").eq("user_id",current_user()["id"]).order("created_at",desc=True).execute()
    return render_template("notifications.html", rows=q.data)

# ---------- Admin / role management ----------
@app.route("/admin")
@admin_required("Admin Assistant")
def admin():
    profiles = supabase.table("profiles").select("*").order("created_at").execute().data
    roles = supabase.table("user_roles").select("*").execute().data
    return render_template("admin.html", profiles=profiles, roles=roles, all_roles=ROLES)

@app.route("/admin/roles", methods=["POST"])
@owner_required
def set_role():
    uid = request.form["user_id"]
    role = request.form["role"]
    if role not in ROLES: abort(400)
    if uid == current_user()["id"]: abort(400)
    supabase.table("user_roles").upsert({"user_id":uid,"role":role}).execute()
    return redirect(url_for("admin"))

@app.route("/admin/roles/remove", methods=["POST"])
@owner_required
def remove_role():
    uid = request.form["user_id"]
    if uid == current_user()["id"]: abort(400)
    supabase.table("user_roles").delete().eq("user_id",uid).execute()
    return redirect(url_for("admin"))

@app.route("/admin/rules")
@admin_required("Junior Administrator")
def admin_rules():
    return redirect(url_for("rules",server=session.get("server","tr")))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
