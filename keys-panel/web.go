package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type session struct {
	csrf    string
	flash   string
	flashOK bool
	expires time.Time
}

type panel struct {
	paths    Paths
	token    string
	listen   string
	mu       sync.Mutex
	sessions map[string]*session
}

func cmdServe(paths Paths, arguments []string) {
	set := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := set.String("listen", "127.0.0.1:9000", "loopback address to bind")
	set.Parse(arguments)

	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		fail("listen must be host:port")
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		fail("listen must use a loopback address; this panel must never be exposed publicly")
	}
	token, err := ensureToken(paths)
	if err != nil {
		fail(err.Error())
	}
	server := &panel{paths: paths, token: token, listen: *listen, sessions: map[string]*session{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/login", server.handleLogin)
	mux.HandleFunc("/logout", server.handleLogout)
	mux.HandleFunc("/keys/add", server.handleAdd)
	mux.HandleFunc("/keys/revoke", server.handleRevoke)
	mux.HandleFunc("/keys/rotate", server.handleRotate)
	mux.HandleFunc("/panel.css", server.handleCSS)
	mux.HandleFunc("/panel.js", server.handleJS)

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           server.guard(mux),
		ReadHeaderTimeout: 5 * time.Second,
		// Key changes restart two services, so a request may legitimately
		// take tens of seconds.
		WriteTimeout:   90 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	log.Printf("tproxy-keys panel on http://%s (token in %s)", *listen, paths.Token)
	if err := httpServer.ListenAndServe(); err != nil {
		fail(err.Error())
	}
}

// guard rejects anything that did not come from a browser pointed at this
// loopback address. The Host check defeats DNS rebinding, which is the one way
// a remote page could otherwise reach a localhost-only service.
func (p *panel) guard(next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(p.listen)
	allowed := map[string]bool{
		"127.0.0.1:" + port: true,
		"localhost:" + port: true,
		"[::1]:" + port:     true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.Host] {
			http.Error(w, "unexpected Host header; reach this panel through an SSH tunnel to localhost", http.StatusForbidden)
			return
		}
		// A browser serialises the Origin of a form navigation as "null" when
		// the page carries Referrer-Policy: no-referrer, so an opaque origin is
		// not evidence of a cross-site request and must not be refused. The Host
		// allowlist above already defeats DNS rebinding, and every mutating
		// handler checks a CSRF token, so only a genuinely foreign origin is
		// rejected here.
		origin := r.Header.Get("Origin")
		if origin == "null" {
			log.Printf("opaque origin accepted for host %q on %s", r.Host, r.URL.Path)
		} else if origin != "" && origin != "http://"+r.Host {
			log.Printf("refused foreign origin %q for host %q on %s", origin, r.Host, r.URL.Path)
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (p *panel) lookup(r *http.Request) (string, *session) {
	cookie, err := r.Cookie("tpk_session")
	if err != nil {
		return "", nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	value, ok := p.sessions[cookie.Value]
	if !ok {
		return "", nil
	}
	if time.Now().After(value.expires) {
		delete(p.sessions, cookie.Value)
		return "", nil
	}
	return cookie.Value, value
}

func (p *panel) setFlash(current *session, message string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	current.flash = message
	current.flashOK = ok
}

func (p *panel) takeFlash(current *session) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	message, ok := current.flash, current.flashOK
	current.flash = ""
	return message, ok
}

func randomHex(size int) string {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return ""
	}
	return hex.EncodeToString(buffer)
}

func (p *panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	supplied := strings.TrimSpace(r.FormValue("token"))
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(p.token)) != 1 {
		p.render(w, "login", map[string]any{"Error": "Неверный токен."})
		return
	}
	id := randomHex(24)
	p.mu.Lock()
	p.sessions[id] = &session{csrf: randomHex(24), expires: time.Now().Add(12 * time.Hour)}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "tpk_session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   12 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	id, current := p.lookup(r)
	if current != nil {
		p.mu.Lock()
		delete(p.sessions, id)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "tpk_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *panel) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	_, current := p.lookup(r)
	if current == nil {
		p.render(w, "login", map[string]any{})
		return
	}
	views, host, err := Keys(p.paths)
	data := map[string]any{
		"Keys":     views,
		"Hostname": host,
		"CSRF":     current.csrf,
		"Ready":    p.readyLabel(),
		"Units":    p.unitStates(),
	}
	if err != nil {
		data["Error"] = err.Error()
	}
	if message, ok := p.takeFlash(current); message != "" {
		data["Flash"] = message
		data["FlashOK"] = ok
	}
	p.render(w, "index", data)
}

func (p *panel) readyLabel() string {
	state, err := readyState(p.paths)
	if err != nil {
		return "недоступен"
	}
	return state
}

func (p *panel) unitStates() []map[string]string {
	result := []map[string]string{}
	for _, unit := range []string{"caddy", "mtproxy", "tproxy-server"} {
		state := "inactive"
		if unitActive(unit + ".service") {
			state = "active"
		}
		result = append(result, map[string]string{"Name": unit, "State": state})
	}
	return result
}

// mutate runs one state-changing action behind the CSRF check and turns its
// result into a flash message.
func (p *panel) mutate(w http.ResponseWriter, r *http.Request, action func(*session) (string, error)) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_, current := p.lookup(r)
	if current == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(current.csrf)) != 1 {
		http.Error(w, "stale form; reload the panel", http.StatusForbidden)
		return
	}
	message, err := action(current)
	if err != nil {
		p.setFlash(current, err.Error(), false)
	} else {
		p.setFlash(current, message, true)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *panel) handleAdd(w http.ResponseWriter, r *http.Request) {
	p.mutate(w, r, func(_ *session) (string, error) {
		name := strings.TrimSpace(r.FormValue("name"))
		label := strings.TrimSpace(r.FormValue("label"))
		mode := strings.TrimSpace(r.FormValue("mode"))
		profile, err := AddKey(p.paths, name, label, mode)
		if err != nil {
			return "", err
		}
		return "Ключ " + profile.Name + " создан, службы перезапущены.", nil
	})
}

func (p *panel) handleRevoke(w http.ResponseWriter, r *http.Request) {
	p.mutate(w, r, func(_ *session) (string, error) {
		name := strings.TrimSpace(r.FormValue("name"))
		if err := RevokeKey(p.paths, name); err != nil {
			return "", err
		}
		return "Ключ " + name + " отозван, службы перезапущены.", nil
	})
}

func (p *panel) handleRotate(w http.ResponseWriter, r *http.Request) {
	p.mutate(w, r, func(_ *session) (string, error) {
		name := strings.TrimSpace(r.FormValue("name"))
		profile, err := RotateKey(p.paths, name)
		if err != nil {
			return "", err
		}
		return "Ключ " + profile.Name + " перевыпущен — старая ссылка больше не работает.", nil
	})
}

func (p *panel) handleCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	fmt.Fprint(w, panelCSS)
}

func (p *panel) handleJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	fmt.Fprint(w, panelJS)
}

func (p *panel) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

var templates = template.Must(template.New("panel").Parse(pageTemplates))
