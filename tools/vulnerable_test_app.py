"""
vulnerable_test_app.py
Glacier's vulnerability testing module - made by HackOps Academy.

A deliberately vulnerable local Flask app, styled as a polished,
realistic storefront (in the spirit of OWASP Juice Shop) rather than
bare unstyled HTML - included ONLY so you have a safe, known target to
test Glacier's active scanner against on your own machine, the same way
a locked practice range works before using a tool for real.

Default login: hackops / hackops

DO NOT expose this outside localhost. DO NOT scan anything else with the
active scanner until you've confirmed detection works correctly here first.

Run with: python3 vulnerable_test_app.py
Then it's up at http://127.0.0.1:5001

Note on the vulnerable code itself: every injectable query, subprocess
call, file path join, and redirect below is byte-for-byte unchanged from
earlier revisions of this file - only the surrounding page chrome
(nav/footer/product cards/styling) was reworked. If you're diffing this
against an older copy, every vulnerability, every route path, every
parameter name, and every detection signature (e.g. "SQLSTATE" in the
SQL error message) is identical. The login form's field names
("username"/"password") are also unchanged, since Glacier's auth module
expects those exact names by default.
"""

import html as html_lib
import os
import subprocess
import sqlite3
import tempfile
import time

from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = "glacier-test-app-not-for-production"

# --- Path traversal target setup ---
_UPLOADS_DIR = tempfile.mkdtemp(prefix="glacier_uploads_")
with open(os.path.join(_UPLOADS_DIR, "readme.txt"), "w") as _f:
    _f.write("This is a normal, intended file in the uploads directory.\n")

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.execute("CREATE TABLE products (id INTEGER, name TEXT, price TEXT, blurb TEXT)")
conn.execute("INSERT INTO products VALUES (1, 'Widget', '$12.00', 'A dependable, all-purpose widget.')")
conn.execute("INSERT INTO products VALUES (2, 'Gadget', '$24.00', 'Does more than a widget. Allegedly.')")
conn.commit()

# SQLite has no SLEEP()/pg_sleep() of its own - registering one lets the
# /slow-product route below stand in for a real time-based-blind target.
conn.create_function("sleep", 1, lambda seconds: time.sleep(seconds) or 0)


# ---------------------------------------------------------------------
# Shared page chrome - every route below builds its actual (vulnerable
# or safe) content exactly as before, then hands it to page() to get a
# consistent header, footer, and styling. None of this touches how any
# of the vulnerable logic works - only presentation changed.
# ---------------------------------------------------------------------

BASE_CSS = """
  :root{
    --bg:#0d1117; --bg-alt:#11161f; --surface:#161c27; --surface-2:#1c2432;
    --line:#232c3d; --line-soft:#1a2130;
    --text:#e7ecf5; --text-dim:#8b96ab; --text-faint:#5b6579;
    --accent:#3fd0c9; --accent-2:#7c8cff; --accent-soft:rgba(63,208,201,0.12);
    --ok:#3fd07f; --warn:#f0b429; --danger:#f0556b;
    --radius:12px; --radius-sm:8px;
    --shadow:0 8px 24px rgba(0,0,0,0.35);
    --shadow-sm:0 2px 8px rgba(0,0,0,0.25);
  }
  *{box-sizing:border-box;}
  html{scroll-behavior:smooth;}
  body{
    margin:0; background:
      radial-gradient(1200px 500px at 15% -10%, rgba(63,208,201,0.08), transparent 60%),
      radial-gradient(900px 400px at 100% 0%, rgba(124,140,255,0.06), transparent 55%),
      var(--bg);
    color:var(--text);
    font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
    min-height:100vh; display:flex; flex-direction:column;
    -webkit-font-smoothing:antialiased;
  }
  a{color:inherit;}

  /* ---- Top utility bar ---- */
  .utilitybar{
    background:var(--bg-alt); border-bottom:1px solid var(--line-soft);
    font-size:12px; color:var(--text-faint); padding:6px 32px;
    display:flex; justify-content:space-between;
  }
  .utilitybar span{letter-spacing:0.2px;}

  /* ---- Nav ---- */
  nav{
    position:sticky; top:0; z-index:20;
    display:flex; align-items:center; gap:28px; padding:14px 32px;
    background:rgba(17,22,31,0.92); backdrop-filter:blur(10px);
    border-bottom:1px solid var(--line);
  }
  nav .brand{display:flex; align-items:center; gap:9px; text-decoration:none; color:var(--text);}
  nav .brand .mark{
    width:30px; height:30px; border-radius:9px; display:flex; align-items:center; justify-content:center;
    background:linear-gradient(135deg,var(--accent),var(--accent-2)); color:#04151a; font-weight:800; font-size:15px;
  }
  nav .brand .name{font-weight:700; letter-spacing:0.2px; font-size:16.5px;}
  nav .navlinks{display:flex; gap:22px; margin-left:6px;}
  nav .navlinks a{color:var(--text-dim); text-decoration:none; font-size:14px; font-weight:500; transition:color .15s;}
  nav .navlinks a:hover{color:var(--accent);}
  nav .spacer{flex:1;}
  .navsearch{display:flex; align-items:center; background:var(--surface); border:1px solid var(--line);
    border-radius:999px; padding:7px 14px; gap:8px; min-width:220px;}
  .navsearch input{background:transparent; border:none; outline:none; color:var(--text); font-size:13.5px; width:100%;}
  .navsearch input::placeholder{color:var(--text-faint);}
  .navsearch .icon{color:var(--text-faint); font-size:13px;}
  .navicons{display:flex; align-items:center; gap:16px;}
  .navicons a{
    color:var(--text-dim); text-decoration:none; font-size:13.5px; font-weight:600;
    display:flex; align-items:center; gap:6px; padding:7px 12px; border-radius:8px; transition:.15s;
  }
  .navicons a:hover{background:var(--surface); color:var(--text);}
  .navicons a.cta{background:var(--accent); color:#04151a;}
  .navicons a.cta:hover{background:var(--accent); opacity:0.9;}

  /* ---- Layout ---- */
  main{flex:1; width:100%;}
  .wrap{max-width:1060px; margin:0 auto; padding:0 32px;}
  .breadcrumbs{font-size:12.5px; color:var(--text-faint); padding:18px 0 0;}
  .breadcrumbs a{color:var(--text-dim); text-decoration:none;}
  .breadcrumbs a:hover{color:var(--accent);}

  /* ---- Hero ---- */
  .hero{
    padding:56px 0 40px; display:flex; align-items:center; justify-content:space-between; gap:40px;
  }
  .hero .eyebrow{color:var(--accent); font-size:12.5px; font-weight:700; letter-spacing:1.5px; text-transform:uppercase;}
  .hero h1{font-size:38px; line-height:1.15; margin:10px 0 14px; letter-spacing:-0.5px;}
  .hero p{color:var(--text-dim); font-size:15.5px; max-width:480px; line-height:1.6;}
  .hero .actions{display:flex; gap:12px; margin-top:22px;}
  .hero-art{
    width:220px; height:170px; border-radius:20px; flex-shrink:0;
    background:linear-gradient(150deg,var(--surface-2),var(--surface));
    border:1px solid var(--line); display:flex; align-items:center; justify-content:center;
    font-size:64px; box-shadow:var(--shadow);
  }

  /* ---- Section heading ---- */
  .section-head{display:flex; align-items:baseline; justify-content:space-between; margin:8px 0 20px;}
  .section-head h2{font-size:20px; margin:0; letter-spacing:-0.2px;}
  .section-head .sub{color:var(--text-faint); font-size:13px;}

  /* ---- Product grid ---- */
  .grid{display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:18px; padding-bottom:36px;}
  .product{
    background:var(--surface); border:1px solid var(--line); border-radius:var(--radius);
    text-decoration:none; color:var(--text); display:flex; flex-direction:column;
    overflow:hidden; transition:transform .18s ease, border-color .18s ease, box-shadow .18s ease;
  }
  .product:hover{transform:translateY(-3px); border-color:rgba(63,208,201,0.4); box-shadow:var(--shadow);}
  .product .thumb{
    height:110px; display:flex; align-items:center; justify-content:center; font-size:40px;
    background:linear-gradient(160deg,var(--surface-2),var(--bg-alt));
    border-bottom:1px solid var(--line);
  }
  .product .body{padding:16px;}
  .product .badge{
    display:inline-block; font-size:10.5px; font-weight:700; letter-spacing:0.4px; text-transform:uppercase;
    padding:3px 8px; border-radius:5px; background:var(--accent-soft); color:var(--accent); margin-bottom:8px;
  }
  .product .name{font-weight:600; font-size:15px;}
  .product .stars{color:var(--warn); font-size:12px; margin-top:5px; letter-spacing:1px;}
  .product .stars .count{color:var(--text-faint); font-weight:400; letter-spacing:0; margin-left:5px;}
  .product .price{color:var(--accent); font-weight:700; margin-top:9px; font-size:15px;}
  .product .price .was{color:var(--text-faint); font-weight:400; text-decoration:line-through; margin-left:7px; font-size:12.5px;}
  .product .blurb{color:var(--text-dim); font-size:12.5px; margin-top:6px; line-height:1.5;}

  /* ---- Cards / generic content ---- */
  .card{background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); padding:24px; margin-bottom:18px; box-shadow:var(--shadow-sm);}
  .panel-title{font-size:12px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase; color:var(--text-faint); margin-bottom:14px;}
  h1.page-title{font-size:25px; margin:18px 0 20px; letter-spacing:-0.3px;}

  /* ---- Buttons ---- */
  button, .btn{
    background:var(--accent); color:#04151a; border:none; padding:11px 20px;
    border-radius:9px; font-weight:700; cursor:pointer; font-size:14px; text-decoration:none;
    display:inline-flex; align-items:center; gap:8px; transition:transform .12s ease, opacity .12s ease;
  }
  button:hover, .btn:hover{opacity:0.92; transform:translateY(-1px);}
  .btn.ghost{background:transparent; color:var(--text); border:1px solid var(--line);}
  .btn.ghost:hover{border-color:var(--accent); color:var(--accent);}

  /* ---- Forms ---- */
  form.stack{display:flex; flex-direction:column; gap:14px; max-width:360px;}
  label{font-size:12.5px; color:var(--text-dim); font-weight:600; margin-bottom:-6px;}
  input[type=text], input[type=password]{
    background:var(--bg-alt); border:1px solid var(--line); color:var(--text);
    padding:11px 13px; border-radius:9px; font-size:14px; outline:none; transition:border-color .15s;
  }
  input:focus{border-color:var(--accent);}
  .hint{color:var(--text-faint); font-size:12.5px; line-height:1.6;}

  /* ---- Alerts ---- */
  .alert{padding:13px 16px; border-radius:9px; margin-top:16px; font-size:13.5px; display:flex; gap:10px; align-items:flex-start; line-height:1.5;}
  .alert.ok{background:rgba(63,208,127,0.1); border:1px solid rgba(63,208,127,0.35); color:var(--ok);}
  .alert.err{background:rgba(240,85,107,0.1); border:1px solid rgba(240,85,107,0.35); color:var(--danger);}
  .alert.info{background:var(--accent-soft); border:1px solid rgba(63,208,201,0.35); color:var(--accent);}

  pre{background:var(--bg-alt); border:1px solid var(--line); border-radius:var(--radius-sm); padding:16px; overflow-x:auto; font-size:12.5px; line-height:1.6; color:var(--text-dim);}

  /* ---- Trust strip ---- */
  .trust{display:flex; gap:28px; padding:22px 0 8px; flex-wrap:wrap; border-top:1px solid var(--line-soft); margin-top:8px;}
  .trust .item{display:flex; align-items:center; gap:9px; color:var(--text-faint); font-size:12.5px;}
  .trust .item .ic{color:var(--accent); font-size:15px;}

  /* ---- Diagnostics panel (QA/status area) ---- */
  .diag{background:var(--bg-alt); border:1px dashed var(--line); border-radius:var(--radius);}
  .diag .diag-head{display:flex; align-items:center; gap:10px; padding:16px 20px; cursor:pointer;}
  .diag .diag-head .dot{width:8px; height:8px; border-radius:50%; background:var(--ok); box-shadow:0 0 0 3px rgba(63,208,127,0.18);}
  .diag .diag-head .title{font-weight:700; font-size:13px;}
  .diag .diag-head .sub{color:var(--text-faint); font-size:12px; margin-left:2px;}
  .diag .diag-body{padding:0 20px 20px;}
  .diag-links{display:flex; flex-wrap:wrap; gap:8px;}
  .diag-links a{
    font-size:11.5px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    background:var(--surface); color:var(--text-dim); padding:5px 10px; border-radius:6px;
    border:1px solid var(--line); text-decoration:none; transition:.15s;
  }
  .diag-links a:hover{border-color:var(--accent); color:var(--accent);}

  /* ---- Footer ---- */
  footer{border-top:1px solid var(--line); background:var(--bg-alt); margin-top:40px;}
  .footer-grid{
    max-width:1060px; margin:0 auto; padding:40px 32px 24px;
    display:grid; grid-template-columns:1.4fr 1fr 1fr 1fr; gap:28px;
  }
  .footer-grid .fbrand{display:flex; align-items:center; gap:9px; margin-bottom:10px;}
  .footer-grid .fbrand .mark{
    width:26px; height:26px; border-radius:8px; display:flex; align-items:center; justify-content:center;
    background:linear-gradient(135deg,var(--accent),var(--accent-2)); color:#04151a; font-weight:800; font-size:13px;
  }
  .footer-grid .fbrand .name{font-weight:700; font-size:14.5px;}
  .footer-grid p{color:var(--text-faint); font-size:12.5px; line-height:1.6; max-width:260px;}
  .footer-grid h4{font-size:12px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); margin:0 0 14px;}
  .footer-grid ul{list-style:none; padding:0; margin:0; display:flex; flex-direction:column; gap:10px;}
  .footer-grid a{color:var(--text-faint); text-decoration:none; font-size:13px;}
  .footer-grid a:hover{color:var(--accent);}
  .footer-bottom{
    border-top:1px solid var(--line-soft); padding:16px 32px; max-width:1060px; margin:0 auto;
    display:flex; justify-content:space-between; color:var(--text-faint); font-size:11.5px; flex-wrap:wrap; gap:8px;
  }

  @media (max-width:720px){
    nav .navlinks, .navsearch, .trust{display:none;}
    .hero{flex-direction:column; align-items:flex-start;}
    .footer-grid{grid-template-columns:1fr 1fr;}
  }
"""


def page(title, body, logged_in=False, breadcrumb=None):
    nav_right = (
        '<a href="/account">Account</a><a href="/logout">Log out</a>'
        if logged_in else
        '<a href="/login">Log in</a>'
    )
    crumb_html = ""
    if breadcrumb:
        parts = [f'<a href="/">Catalog</a>'] + [
            f'<a href="{href}">{html_lib.escape(label)}</a>' if href else f'<span>{html_lib.escape(label)}</span>'
            for label, href in breadcrumb
        ]
        crumb_html = f'<div class="breadcrumbs wrap">{" &nbsp;/&nbsp; ".join(parts)}</div>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html_lib.escape(title)} &middot; Northwind Supply Co.</title>
<style>{BASE_CSS}</style></head>
<body>
<div class="utilitybar"><span>Free shipping on orders over $50</span><span>Support: hackops-academy.test</span></div>
<nav>
  <a class="brand" href="/"><span class="mark">N</span><span class="name">Northwind Supply Co.</span></a>
  <div class="navlinks">
    <a href="/">Catalog</a>
    <a href="/#deals">Deals</a>
    <a href="/#new">New Arrivals</a>
  </div>
  <span class="spacer"></span>
  <form class="navsearch" action="/search" method="get">
    <span class="icon">&#128269;</span>
    <input type="text" name="q" placeholder="Search products&hellip;">
  </form>
  <div class="navicons">{nav_right}<a class="cta" href="/#catalog">&#128722;&nbsp;Cart</a></div>
</nav>
{crumb_html}
<main><div class="wrap">{body}</div></main>
<footer>
  <div class="footer-grid">
    <div>
      <div class="fbrand"><span class="mark">N</span><span class="name">Northwind Supply Co.</span></div>
      <p>A demo storefront built for Glacier's active scanner - every page here is intentionally vulnerable (or, on the "safe-" routes, intentionally guarded) for authorized security testing practice only.</p>
    </div>
    <div>
      <h4>Shop</h4>
      <ul><li><a href="/">Catalog</a></li><li><a href="/#deals">Deals</a></li><li><a href="/#new">New Arrivals</a></li></ul>
    </div>
    <div>
      <h4>Support</h4>
      <ul><li><a href="/login">Log in</a></li><li><a href="/account">My Account</a></li><li><a href="/#catalog">Help Center</a></li></ul>
    </div>
    <div>
      <h4>Company</h4>
      <ul><li><a href="/#catalog">About</a></li><li><a href="/#catalog">Careers</a></li><li><a href="/#catalog">Contact</a></li></ul>
    </div>
  </div>
  <div class="footer-bottom">
    <span>&copy; Glacier vulnerability testing module &middot; made by HackOps Academy</span>
    <span>localhost only &middot; not a real store &middot; not for production</span>
  </div>
</footer>
</body></html>"""


def diagnostics_panel():
    """A tastefully out-of-the-way panel exposing every test route, so
    the site still reads as a real storefront at a glance while keeping
    every endpoint one click away for the spider/scanner to discover."""
    return """
    <div class="diag">
      <div class="diag-head">
        <span class="dot"></span>
        <span class="title">QA &amp; Diagnostics</span>
        <span class="sub">internal test routes for Glacier's active scanner</span>
      </div>
      <div class="diag-body">
        <div class="diag-links">
          <a href="/search?q=widget">/search</a>
          <a href="/safe-search?q=widget">/safe-search</a>
          <a href="/product?id=1">/product</a>
          <a href="/blind-product?id=1">/blind-product</a>
          <a href="/slow-product?id=1">/slow-product</a>
          <a href="/read-file?file=readme.txt">/read-file</a>
          <a href="/safe-read-file?file=readme.txt">/safe-read-file</a>
          <a href="/ping?host=127.0.0.1">/ping</a>
          <a href="/ping-slow?host=127.0.0.1">/ping-slow</a>
          <a href="/safe-ping?host=127.0.0.1">/safe-ping</a>
          <a href="/go?url=/">/go</a>
          <a href="/safe-go?url=/">/safe-go</a>
          <a href="/login">/login</a>
          <a href="/account?id=1">/account</a>
        </div>
      </div>
    </div>
    """


def _is_logged_in():
    return bool(session.get("logged_in"))


# ---------------------------------------------------------------------
# Routes - the actual request handling/vulnerable logic in each of
# these is unchanged; only the returned HTML got a full redesign.
# ---------------------------------------------------------------------

@app.route("/")
def home():
    body = f"""
    <div class="hero" id="catalog">
      <div>
        <div class="eyebrow">New season, new gear</div>
        <h1>Precision tools.<br>Professional grade.</h1>
        <p>Northwind Supply Co. stocks the parts and diagnostics gear your bench actually needs - dependable, in stock, shipped fast.</p>
        <div class="actions">
          <a class="btn" href="#deals">Shop the catalog</a>
          <a class="btn ghost" href="/account">My account</a>
        </div>
      </div>
      <div class="hero-art">&#128295;</div>
    </div>

    <div class="trust">
      <div class="item"><span class="ic">&#9989;</span> Free shipping over $50</div>
      <div class="item"><span class="ic">&#9989;</span> 2-year warranty</div>
      <div class="item"><span class="ic">&#9989;</span> 24/7 support</div>
      <div class="item"><span class="ic">&#9989;</span> Easy 30-day returns</div>
    </div>

    <div class="section-head" id="deals">
      <h2>Featured products</h2>
      <span class="sub">2 items</span>
    </div>
    <div class="grid" id="new">
      <a class="product" href="/product?id=1">
        <div class="thumb">&#128295;</div>
        <div class="body">
          <span class="badge">Best seller</span>
          <div class="name">Widget</div>
          <div class="stars">&#9733;&#9733;&#9733;&#9733;&#9734;<span class="count">(128)</span></div>
          <div class="price">$12.00</div>
          <div class="blurb">A dependable, all-purpose widget.</div>
        </div>
      </a>
      <a class="product" href="/product?id=2">
        <div class="thumb">&#9881;&#65039;</div>
        <div class="body">
          <span class="badge">New</span>
          <div class="name">Gadget</div>
          <div class="stars">&#9733;&#9733;&#9733;&#9733;&#9733;<span class="count">(64)</span></div>
          <div class="price">$24.00<span class="was">$29.00</span></div>
          <div class="blurb">Does more than a widget. Allegedly.</div>
        </div>
      </a>
      <a class="product" href="/blind-product?id=1">
        <div class="thumb">&#128269;</div>
        <div class="body">
          <span class="badge">QA</span>
          <div class="name">Widget &mdash; availability check</div>
          <div class="stars">&#9733;&#9733;&#9733;&#9733;&#9734;<span class="count">(blind test)</span></div>
          <div class="blurb">Stock lookup with no error detail exposed.</div>
        </div>
      </a>
      <a class="product" href="/slow-product?id=1">
        <div class="thumb">&#8987;</div>
        <div class="body">
          <span class="badge">QA</span>
          <div class="name">Widget &mdash; extended lookup</div>
          <div class="stars">&#9733;&#9733;&#9733;&#9734;&#9734;<span class="count">(timing test)</span></div>
          <div class="blurb">Slower catalog lookup path.</div>
        </div>
      </a>
    </div>

    {diagnostics_panel()}
    """
    return page("Catalog", body, logged_in=_is_logged_in())


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Deliberately vulnerable: reflects user input into HTML unescaped.
    body = f"""
    <h1 class="page-title">Search results</h1>
    <form class="navsearch" style="max-width:420px; margin-bottom:22px;" action="/search" method="get">
      <span class="icon">&#128269;</span>
      <input type="text" name="q" value="" placeholder="Search products&hellip;">
      <button type="submit" style="padding:7px 16px;">Go</button>
    </form>
    <div class="card"><p>Results for: {q}</p><p class="hint">No results found. Try a different search term, or browse the full catalog.</p></div>
    """
    return page("Search", body, logged_in=_is_logged_in(), breadcrumb=[("Search", None)])


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    # Deliberately vulnerable: string-concatenated SQL, no parameterization.
    query = f"SELECT name FROM products WHERE id = {pid}"
    try:
        cur = conn.execute(query)
        row = cur.fetchone()
        name = row[0] if row else "Not found"
        body = f"""
        <h1 class="page-title">{name}</h1>
        <div class="card" style="display:flex; gap:24px; align-items:center;">
          <div class="thumb" style="width:120px; height:120px; flex-shrink:0; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:42px; background:linear-gradient(160deg,var(--surface-2),var(--bg-alt)); border:1px solid var(--line);">&#128295;</div>
          <div>
            <div class="stars">&#9733;&#9733;&#9733;&#9733;&#9734;<span class="count">(128 reviews)</span></div>
            <p style="color:var(--text-dim); margin:10px 0 16px; font-size:14px;">Product ID: {pid}</p>
            <button>Add to cart</button>
          </div>
        </div>
        """
        return page(name, body, logged_in=_is_logged_in(), breadcrumb=[("Product", None)])
    except sqlite3.OperationalError as e:
        # This error message leaking to the response is exactly the
        # signature the active scanner's SQLi detection looks for.
        body = f'<h1 class="page-title">Product</h1><div class="alert err">SQL error: SQLSTATE - {e}</div>'
        return page("Product", body, logged_in=_is_logged_in(), breadcrumb=[("Product", None)]), 500


@app.route("/blind-product")
def blind_product():
    pid = request.args.get("id", "1")
    # Deliberately vulnerable, and deliberately suppresses the DB error
    # message - the only signal is whether the page says "found" or
    # "not found". This is what check_boolean_blind_sqli() is meant to
    # catch.
    query = f"SELECT name FROM products WHERE id = {pid}"
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row:
        body = '<h1 class="page-title">Availability check</h1><div class="alert ok">&#9989; This item is in stock.</div>'
        return page("Product", body, logged_in=_is_logged_in(), breadcrumb=[("Availability", None)])
    body = '<h1 class="page-title">Availability check</h1><div class="alert err">&#10060; No such product exists.</div>'
    return page("Product", body, logged_in=_is_logged_in(), breadcrumb=[("Availability", None)]), 404


@app.route("/slow-product")
def slow_product():
    pid = request.args.get("id", "1")
    # Same idea as /blind-product, but leaks nothing either way - the
    # only signal is response timing. This is what
    # check_time_based_blind_sqli() is meant to catch.
    query = f"SELECT name FROM products WHERE id = {pid}"
    try:
        conn.execute(query).fetchone()
    except sqlite3.OperationalError:
        pass
    body = '<h1 class="page-title">Extended lookup</h1><div class="alert err">&#10060; No such product exists.</div>'
    return page("Product", body, logged_in=_is_logged_in(), breadcrumb=[("Extended lookup", None)]), 404


@app.route("/safe-search")
def safe_search():
    q = request.args.get("q", "")
    # Correctly escaped, for comparison - the scanner should NOT flag this.
    body = f"""
    <h1 class="page-title">Search results</h1>
    <div class="card"><p>Results for: {html_lib.escape(q)}</p></div>
    """
    return page("Search", body, logged_in=_is_logged_in(), breadcrumb=[("Search (safe)", None)])


@app.route("/read-file")
def read_file():
    filename = request.args.get("file", "readme.txt")
    # Deliberately vulnerable: naive string-join of user input into a
    # path with no normalization/allow-list. This is what
    # check_path_traversal() is meant to catch.
    path = os.path.join(_UPLOADS_DIR, filename)
    try:
        with open(path) as f:
            content = f.read()
        body = f'<h1 class="page-title">Document viewer</h1><div class="card"><div class="panel-title">{html_lib.escape(filename)}</div><pre>{html_lib.escape(content)}</pre></div>'
        return page("Document viewer", body, logged_in=_is_logged_in(), breadcrumb=[("Documents", None)])
    except OSError as e:
        body = f'<h1 class="page-title">Document viewer</h1><div class="alert err">{html_lib.escape(str(e))}</div>'
        return page("Document viewer", body, logged_in=_is_logged_in(), breadcrumb=[("Documents", None)]), 404


@app.route("/safe-read-file")
def safe_read_file():
    filename = request.args.get("file", "readme.txt")
    # Correctly guarded: resolves the real path and rejects anything
    # that escapes _UPLOADS_DIR - the scanner should NOT flag this.
    requested = os.path.realpath(os.path.join(_UPLOADS_DIR, filename))
    uploads_real = os.path.realpath(_UPLOADS_DIR)
    if requested != uploads_real and not requested.startswith(uploads_real + os.sep):
        body = '<h1 class="page-title">Document viewer</h1><div class="alert err">Forbidden: path escapes uploads directory.</div>'
        return page("Document viewer", body, logged_in=_is_logged_in(), breadcrumb=[("Documents (safe)", None)]), 403
    try:
        with open(requested) as f:
            content = f.read()
        body = f'<h1 class="page-title">Document viewer</h1><div class="card"><div class="panel-title">{html_lib.escape(filename)}</div><pre>{html_lib.escape(content)}</pre></div>'
        return page("Document viewer", body, logged_in=_is_logged_in(), breadcrumb=[("Documents (safe)", None)])
    except OSError as e:
        body = f'<h1 class="page-title">Document viewer</h1><div class="alert err">{html_lib.escape(str(e))}</div>'
        return page("Document viewer", body, logged_in=_is_logged_in(), breadcrumb=[("Documents (safe)", None)]), 404


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Deliberately vulnerable: shell=True with string-concatenated input.
    # This is what check_command_injection()'s reflected-output check is
    # meant to catch.
    try:
        output = subprocess.run(
            f"ping -c 1 {host}", shell=True, capture_output=True,
            text=True, timeout=10,
        )
        combined = html_lib.escape(output.stdout + output.stderr)
        body = f'<h1 class="page-title">Network diagnostics</h1><div class="card"><div class="panel-title">Ping result</div><pre>{combined}</pre></div>'
        return page("Diagnostics", body, logged_in=_is_logged_in(), breadcrumb=[("Diagnostics", None)])
    except subprocess.TimeoutExpired:
        body = '<h1 class="page-title">Network diagnostics</h1><div class="alert err">Timed out.</div>'
        return page("Diagnostics", body, logged_in=_is_logged_in(), breadcrumb=[("Diagnostics", None)]), 504


@app.route("/ping-slow")
def ping_slow():
    host = request.args.get("host", "127.0.0.1")
    # Same vulnerable pattern as /ping, but output is discarded - only
    # signal is timing. This is what check_blind_command_injection() is
    # meant to catch.
    try:
        subprocess.run(
            f"ping -c 1 {host}", shell=True, capture_output=True,
            text=True, timeout=20,
        )
    except subprocess.TimeoutExpired:
        pass
    body = '<h1 class="page-title">Network diagnostics</h1><div class="alert ok">&#9989; Request processed.</div>'
    return page("Diagnostics", body, logged_in=_is_logged_in(), breadcrumb=[("Diagnostics", None)])


@app.route("/safe-ping")
def safe_ping():
    host = request.args.get("host", "127.0.0.1")
    # Correctly guarded: shell=False with an argument list - the scanner
    # should NOT flag this as command injection.
    try:
        output = subprocess.run(
            ["ping", "-c", "1", host], shell=False, capture_output=True,
            text=True, timeout=10,
        )
        combined = html_lib.escape(output.stdout + output.stderr)
        body = f'<h1 class="page-title">Network diagnostics</h1><div class="card"><div class="panel-title">Ping result</div><pre>{combined}</pre></div>'
        return page("Diagnostics", body, logged_in=_is_logged_in(), breadcrumb=[("Diagnostics (safe)", None)])
    except (subprocess.TimeoutExpired, OSError) as e:
        body = f'<h1 class="page-title">Network diagnostics</h1><div class="alert err">{html_lib.escape(str(e))}</div>'
        return page("Diagnostics", body, logged_in=_is_logged_in(), breadcrumb=[("Diagnostics (safe)", None)]), 400


@app.route("/go")
def go():
    url = request.args.get("url", "/")
    # Deliberately vulnerable: redirects straight to whatever the caller
    # supplied. This is what check_open_redirect() is meant to catch.
    return redirect(url)


@app.route("/safe-go")
def safe_go():
    url = request.args.get("url", "/")
    # Correctly guarded: only allows relative, same-site paths.
    if url.startswith("/") and not url.startswith("//") and "\\" not in url and ":" not in url:
        return redirect(url)
    return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        body = """
        <div style="max-width:400px; margin:32px auto 0;">
          <h1 class="page-title" style="text-align:center;">Welcome back</h1>
          <div class="card">
            <form class="stack" method="post">
              <label>Username</label>
              <input name="username" type="text" placeholder="Username" autocomplete="username">
              <label>Password</label>
              <input name="password" type="password" placeholder="Password" autocomplete="current-password">
              <button type="submit" style="margin-top:6px;">Log in</button>
            </form>
            <p class="hint" style="margin-top:16px;">Default credentials for testing: <strong>hackops</strong> / <strong>hackops</strong></p>
          </div>
        </div>
        """
        return page("Log in", body, logged_in=_is_logged_in(), breadcrumb=[("Log in", None)])
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == "hackops" and password == "hackops":
        session["logged_in"] = True
        body = '<div style="max-width:400px; margin:32px auto 0;"><h1 class="page-title" style="text-align:center;">Welcome back!</h1><div class="alert ok">&#9989; Login successful.</div></div>'
        return page("Welcome", body, logged_in=True, breadcrumb=[("Log in", None)])
    body = '<div style="max-width:400px; margin:32px auto 0;"><h1 class="page-title" style="text-align:center;">Welcome back</h1><div class="alert err">&#10060; Invalid credentials.</div></div>'
    return page("Log in", body, logged_in=_is_logged_in(), breadcrumb=[("Log in", None)]), 401


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    body = '<h1 class="page-title">Logged out</h1><p class="hint">You have been signed out.</p>'
    return page("Logged out", body, logged_in=False, breadcrumb=[("Logged out", None)])


@app.route("/account")
def account():
    if not session.get("logged_in"):
        body = '<h1 class="page-title">Please log in</h1><div class="alert err">You must be logged in to view this page.</div>'
        return page("Please log in", body, logged_in=False, breadcrumb=[("Account", None)]), 401
    # Deliberately vulnerable to SQLi, but ONLY reachable while
    # authenticated - this is the endpoint that proves auth support
    # actually unlocks testing of protected areas, not just that login
    # itself works.
    order_id = request.args.get("id", "1")
    query = f"SELECT name FROM products WHERE id = {order_id}"
    try:
        cur = conn.execute(query)
        row = cur.fetchone()
        name = row[0] if row else "Not found"
        body = f"""
        <h1 class="page-title">My Account</h1>
        <div class="card">
          <div class="panel-title">Signed in as</div>
          <p style="font-size:15px; font-weight:600;">hackops</p>
          <div class="panel-title" style="margin-top:18px;">Order lookup</div>
          <p style="font-size:15px;">{name}</p>
        </div>
        """
        return page("My Account", body, logged_in=True, breadcrumb=[("Account", None)])
    except sqlite3.OperationalError as e:
        body = f'<h1 class="page-title">My Account</h1><div class="alert err">SQL error: SQLSTATE - {e}</div>'
        return page("My Account", body, logged_in=True, breadcrumb=[("Account", None)]), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
