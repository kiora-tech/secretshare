"""Parcours complets dans un vrai navigateur : le chiffrement ne se teste qu'ici.

    docker run --rm --network host -v "$PWD/tests/e2e:/e2e" -v /tmp/shots:/out \
        mcr.microsoft.com/playwright/python:v1.51.0-noble \
        python /e2e/e2e.py http://localhost:18108 /out
"""
import re
import sys

from playwright.sync_api import sync_playwright, expect

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:18108"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp"
SECRET = "hunter2 · mot de passe 🔑\nligne 2"
failures = []


def check(label, condition):
    print(("✓ " if condition else "✗ ") + label)
    if not condition:
        failures.append(label)


def watch(page, sink):
    page.on("console", lambda m: sink.append(m.text) if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: sink.append(str(e)))


def visit(browser, url, sink):
    """Un onglet neuf par ouverture, comme un destinataire qui clique sur le lien."""
    page = browser.new_page()
    watch(page, sink)
    page.goto(url)
    return page


def hold(page, button="#reveal-submit", ready="#reveal-ready", ms=1200):
    """Appui maintenu, comme un humain ; un clic seul ne déclenche rien."""
    if ready:
        page.wait_for_selector(f"{ready}:not([hidden])")
    page.hover(button)
    page.mouse.down()
    page.wait_for_timeout(ms)
    page.mouse.up()


def create(browser, text, views=1, passphrase=None, file=None):
    page = browser.new_page()
    logs = []
    watch(page, logs)
    page.goto(BASE + "/")
    page.fill("#secret-text", text)
    for _ in range(views - 1):
        page.click("[data-step='1']")
    if passphrase:
        page.check("#passphrase-toggle")
        page.fill("#passphrase", passphrase)
    if file:
        page.set_input_files("#secret-files", file)
    page.click("#create-submit")
    page.wait_for_selector("#create-result:not([hidden])", timeout=30000)
    share = page.input_value("#share-link")
    manage = page.input_value("#manage-link")
    page.close()
    return share, manage, logs


with sync_playwright() as p:
    browser = p.chromium.launch()
    console = []

    # Accueil, ordinateur et mobile
    page = browser.new_page(viewport={"width": 1366, "height": 900})
    watch(page, console)
    page.goto(BASE + "/")
    page.wait_for_timeout(1200)
    page.screenshot(path=f"{OUT}/home-desktop.png", full_page=True)
    page.close()
    page = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    page.goto(BASE + "/")
    page.wait_for_timeout(1200)
    page.screenshot(path=f"{OUT}/home-mobile.png", full_page=True)
    page.close()

    # 1. Secret à deux vues
    share, manage, logs = create(browser, SECRET, views=2)
    console += logs
    check("lien de partage avec clé dans le fragment", re.match(BASE + r"/s/[\w-]{22}#[\w-]{43}$", share) is not None)
    reader = visit(browser, share, console)
    reader.wait_for_selector("#reveal-ready:not([hidden])")
    reader.wait_for_timeout(900)
    check("page de lecture : 2 vues restantes", reader.inner_text("#reveal-views") == "2 times")
    reader.screenshot(path=f"{OUT}/reveal-ready.png")
    hold(reader)
    reader.wait_for_selector("#reveal-open:not([hidden])")
    reader.wait_for_timeout(900)
    check("1re lecture : texte identique (Unicode, retours à la ligne)", reader.inner_text("#reveal-text") == SECRET)
    check("1re lecture : clé retirée de l'URL", "#" not in reader.url)
    reader.screenshot(path=f"{OUT}/reveal-open.png")
    reader = visit(browser, share, console)
    hold(reader)
    reader.wait_for_selector("#reveal-open:not([hidden])")
    check("2e lecture : tampon « Destroyed »", reader.is_visible("#reveal-status"))
    reader = visit(browser, share, console)
    reader.wait_for_selector("#reveal-gone:not([hidden])")
    check("3e ouverture : secret disparu", True)
    reader.screenshot(path=f"{OUT}/reveal-gone.png")

    tracker = visit(browser, manage, console)
    tracker.wait_for_selector("#manage-found:not([hidden])")
    check("suivi : 2 vues sur 2", tracker.inner_text("#manage-views") == "2 of 2")
    check("suivi : pas de bouton de destruction une fois lu", not tracker.is_visible("#manage-burn"))
    tracker.screenshot(path=f"{OUT}/manage.png")

    # 1 bis. Un scanner qui clique sur le bouton ne consomme rien
    share, manage, logs = create(browser, "scanner-proof")
    scanner = visit(browser, share, console)
    scanner.wait_for_selector("#reveal-ready:not([hidden])")
    scanner.click("#reveal-submit")
    scanner.wait_for_timeout(1500)
    check("un clic seul ne révèle rien", scanner.is_visible("#reveal-ready") and not scanner.is_visible("#reveal-open"))
    reader = visit(browser, share, console)
    hold(reader)
    reader.wait_for_selector("#reveal-open:not([hidden])")
    check("après le clic du scanner, l'humain lit toujours le secret", reader.inner_text("#reveal-text") == "scanner-proof")

    # 2. Phrase de passe
    share, manage, logs = create(browser, "with passphrase", passphrase="correct horse")
    console += logs
    reader = visit(browser, share, console)
    reader.wait_for_selector("#reveal-pass-field:not([hidden])")
    reader.fill("#reveal-pass", "wrong horse")
    hold(reader)
    reader.wait_for_selector("#reveal-error:not([hidden])", timeout=30000)
    check("mauvaise phrase : 9 essais restants", "9 attempts left" in reader.inner_text("#reveal-error"))
    reader.fill("#reveal-pass", "correct horse")
    hold(reader)
    reader.wait_for_selector("#reveal-open:not([hidden])", timeout=30000)
    check("bonne phrase : secret lu", reader.inner_text("#reveal-text") == "with passphrase")

    # 2 bis. Métadonnées en erreur (quota, panne) : un appui ne doit user aucun essai sans la phrase
    share, manage, logs = create(browser, "meta error", passphrase="correct horse")
    reader = browser.new_page()
    watch(reader, [])  # le 429 simulé s'affiche en console comme une ressource en échec
    sent = []
    reader.on("request", lambda r: sent.append(r.url) if r.method == "POST" and "/api/secrets/" in r.url else None)
    first = {"done": False}

    def flaky(route):
        if route.request.method == "GET" and not first["done"]:
            first["done"] = True
            route.fulfill(status=429, content_type="application/json", body='{"error":"rate_limited"}')
        else:
            route.continue_()

    reader.route("**/api/secrets/*", flaky)
    reader.goto(share)
    reader.wait_for_selector("#reveal-error:not([hidden])")
    hold(reader)
    reader.wait_for_selector("#reveal-pass-field:not([hidden])")
    reader.wait_for_timeout(500)
    check("après un 429, l'appui relit l'état sans rien envoyer", sent == [])
    tracker = visit(browser, manage, console)
    tracker.wait_for_selector("#manage-found:not([hidden])")
    check("après un 429, le secret est intact", tracker.inner_text("#manage-views") == "0 of 1")
    reader.fill("#reveal-pass", "correct horse")
    hold(reader)
    reader.wait_for_selector("#reveal-open:not([hidden])", timeout=30000)
    check("après un 429, la bonne phrase ouvre le secret", reader.inner_text("#reveal-text") == "meta error")

    # 3. Destruction par l'expéditeur
    share, manage, logs = create(browser, "to be burned")
    tracker = visit(browser, manage, console)
    tracker.wait_for_selector("#manage-burn")
    tracker.click("#manage-burn")
    tracker.click("#manage-burn")
    tracker.wait_for_timeout(800)
    check("suivi : deux clics ne brûlent rien", tracker.is_visible("#manage-burn"))
    hold(tracker, "#manage-burn", ready="#manage-found")
    tracker.wait_for_selector("#manage-status:not([hidden])")
    check("suivi : brûlé", tracker.text_content("#manage-status") == "Burned")
    reader = visit(browser, share, console)
    reader.wait_for_selector("#reveal-gone:not([hidden])")
    check("brûlé : le lien ne montre plus rien", True)

    # 4. Fichier joint
    share, manage, logs = create(browser, "", file={"name": "contrat.pdf", "mimeType": "application/pdf", "buffer": b"%PDF-1.4 test" * 1000})
    reader = visit(browser, share, console)
    hold(reader)
    reader.wait_for_selector("#reveal-files a")
    with reader.expect_download() as download:
        reader.click("#reveal-files a")
    path = download.value.path()
    check("fichier : nom et contenu intacts", download.value.suggested_filename == "contrat.pdf" and open(path, "rb").read() == b"%PDF-1.4 test" * 1000)

    # Le type du blob se lit par fetch(), que la CSP de la page interdit (connect-src 'self') :
    # ces vérifications passent par un contexte qui l'ignore, hors du relevé des erreurs.
    blob_type = "async () => (await fetch(document.querySelector('#reveal-files a').href)).headers.get('content-type')"
    loose = browser.new_context(bypass_csp=True)
    share, manage, logs = create(browser, "", file={"name": "scan.pdf", "mimeType": "application/pdf", "buffer": b"%PDF-1.4"})
    reader = loose.new_page()
    reader.goto(share)
    hold(reader)
    reader.wait_for_selector("#reveal-files a")
    check("fichier PDF : type conservé", reader.evaluate(blob_type) == "application/pdf")

    # 4 bis. Un fichier HTML ou SVG n'est jamais servi comme une page du site, et un nom piégé
    # par un contrôle de direction Unicode est nettoyé.
    share, manage, logs = create(browser, "", file={"name": "invoice\u202efdp.html", "mimeType": "text/html", "buffer": b"<script>document.title='ran'</script>"})
    reader = loose.new_page()
    reader.goto(share)
    hold(reader)
    reader.wait_for_selector("#reveal-files a")
    check("fichier HTML : servi en application/octet-stream", reader.evaluate(blob_type) == "application/octet-stream")
    check("fichier HTML : contrôle de direction retiré du nom", reader.get_attribute("#reveal-files a", "download") == "invoicefdp.html")

    # 5. Demande de secret (X-Wing)
    asker = browser.new_page()
    watch(asker, console)
    asker.goto(BASE + "/request")
    asker.fill("#request-note", "The router admin password, please")
    asker.click("#request-submit")
    asker.wait_for_selector("#request-result:not([hidden])", timeout=30000)
    request_link = asker.input_value("#request-link")
    inbox_link = asker.input_value("#inbox-link")
    asker.screenshot(path=f"{OUT}/request-created.png")
    check("lien de demande et lien de réception distincts", "/r/" in request_link and "/i/" in inbox_link)

    asker = visit(browser, inbox_link, console)
    asker.wait_for_selector("#inbox-pending:not([hidden])")
    check("boîte : en attente", True)

    tampered = re.sub(r"#.", "#A" if not request_link.split("#")[1].startswith("A") else "#B", request_link)
    # Le déchiffrement de la note échoue exprès ici : son OperationError n'est pas une panne.
    responder = visit(browser, tampered, [])
    responder.wait_for_selector("#respond-broken:not([hidden])")
    check("lien de demande altéré : refus d'envoyer", True)

    responder = visit(browser, request_link, console)
    responder.wait_for_selector("#respond-form:not([hidden])")
    check("correspondant : la note du demandeur s'affiche", responder.inner_text("#respond-note") == "The router admin password, please")
    responder.screenshot(path=f"{OUT}/respond.png")
    responder.fill("#respond-text", "R0uter!admin")
    responder.click("#respond-submit")
    responder.wait_for_selector("#respond-sent:not([hidden])", timeout=30000)
    check("réponse envoyée", True)

    asker = visit(browser, inbox_link, console)
    asker.wait_for_selector("#inbox-ready:not([hidden])")
    asker.wait_for_timeout(1500)
    check("boîte : ouvrir la page ne consomme pas la réponse", not asker.is_visible("#inbox-open"))
    asker.click("#inbox-submit")
    asker.wait_for_timeout(1500)
    check("boîte : un clic seul n'ouvre rien", asker.is_visible("#inbox-ready") and not asker.is_visible("#inbox-open"))
    asker = visit(browser, inbox_link, console)
    hold(asker, "#inbox-submit", ready="#inbox-ready")
    asker.wait_for_selector("#inbox-open:not([hidden])")
    asker.wait_for_timeout(900)
    check("boîte : réponse déchiffrée après l'appui maintenu", asker.inner_text("#inbox-text") == "R0uter!admin")
    check("boîte : clé privée retirée de l'URL", "#" not in asker.url)
    asker.screenshot(path=f"{OUT}/inbox-open.png")
    asker = visit(browser, inbox_link, console)
    asker.wait_for_selector("#inbox-gone:not([hidden])")
    check("boîte : réponse montrée une seule fois", True)

    # 6. Annuler une demande : appui maintenu aussi
    asker = browser.new_page()
    watch(asker, console)
    asker.goto(BASE + "/request")
    asker.click("#request-submit")
    asker.wait_for_selector("#request-result:not([hidden])", timeout=30000)
    request_link = asker.input_value("#request-link")
    inbox_link = asker.input_value("#inbox-link")
    asker = visit(browser, inbox_link, console)
    asker.wait_for_selector("#inbox-pending:not([hidden])")
    asker.click("#inbox-cancel")
    asker.wait_for_timeout(800)
    check("annulation : un clic ne suffit pas", asker.is_visible("#inbox-pending"))
    hold(asker, "#inbox-cancel", ready="#inbox-pending")
    asker.wait_for_selector("#inbox-gone:not([hidden])")
    responder = visit(browser, request_link, console)
    responder.wait_for_selector("#respond-gone:not([hidden])")
    check("annulation : le lien de demande ne s'ouvre plus", True)

    csp = [line for line in console if "Content Security Policy" in line or "Refused" in line]
    check("aucune violation de CSP", not csp)
    errors = [line for line in console if "Failed to load resource" not in line]
    check("aucune erreur JavaScript", not errors)
    if csp or errors:
        print("\n".join((csp + errors)[:10]))

    browser.close()

print("\nTOUT BON" if not failures else f"\n{len(failures)} ÉCHEC(S)")
sys.exit(1 if failures else 0)
