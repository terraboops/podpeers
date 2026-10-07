"""Scene 2: the web UI, driven in Firefox, rendered frame by frame.

Usage: python3 browser.py URL OUTDIR
Writes OUTDIR/frame-00000.png ... at 10 frames per second of demo time. The
cursor is an overlay drawn only for the recording; every click is a real click
event on the real page.
"""
import os, sys, time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

URL, OUT = sys.argv[1], sys.argv[2]
FPS = 10
os.makedirs(OUT, exist_ok=True)
o = Options()
o.add_argument("-headless")
o.add_argument("--width=1280")
o.add_argument("--height=820")
d = webdriver.Firefox(options=o)
frame = 0

def shot(hold=0.0):
    """Save the current page; repeat it to fill `hold` seconds."""
    global frame
    path = os.path.join(OUT, f"frame-{frame:05d}.png")
    d.save_screenshot(path)
    frame += 1
    for _ in range(max(0, round(hold * FPS) - 1)):
        os.link(path, os.path.join(OUT, f"frame-{frame:05d}.png"))
        frame += 1

CURSOR = """
const c = document.createElement('div'); c.id = '__cursor';
c.style.cssText = 'position:fixed;left:0;top:0;z-index:99999;pointer-events:none;transition:none';
c.innerHTML = '<svg width="26" height="30" viewBox="0 0 26 30"><path d="M2 2 L2 24 L8 18 L12 28 L16 26 L12 17 L21 17 Z" fill="#111" stroke="#fff" stroke-width="2"/></svg>';
document.body.appendChild(c);
"""

def cursor_to(x, y):
    d.execute_script("const c=document.getElementById('__cursor'); c.style.left=arguments[0]+'px'; c.style.top=arguments[1]+'px';", x, y)

pos = [1100, 700]

def move(x, y, secs=0.6):
    n = max(1, round(secs * FPS))
    sx, sy = pos
    for i in range(1, n + 1):
        t = i / n
        t = t * t * (3 - 2 * t)  # ease in-out
        cursor_to(sx + (x - sx) * t, sy + (y - sy) * t)
        shot()
    pos[:] = [x, y]

def center_of_node(label):
    return d.execute_script("""
      const g = [...document.querySelectorAll('svg .n')].find(g => g.querySelector('.nlabel').textContent === arguments[0]);
      const r = g.querySelector('.shape').getBoundingClientRect();
      return [r.left + r.width / 2, r.top + r.height / 2];""", label)

def click_node(label):
    d.execute_script("""
      const g = [...document.querySelectorAll('svg .n')].find(g => g.querySelector('.nlabel').textContent === arguments[0]);
      g.dispatchEvent(new MouseEvent('click', {bubbles: true}));""", label)

try:
    d.get(URL)
    time.sleep(1.5)
    d.execute_script(CURSOR)
    cursor_to(*pos)
    shot(1.2)
    x, y = center_of_node("cart")
    move(x - 4, y - 6)
    click_node("cart")
    time.sleep(0.2)
    shot(2.3)
    x, y = center_of_node("frontend")
    move(x - 4, y - 6)
    click_node("frontend")
    time.sleep(0.2)
    shot(1.8)
finally:
    d.quit()
print(f"{frame} frames")
