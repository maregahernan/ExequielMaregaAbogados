/**
 * ============================================================
 * main.js — Exequiel Marega Abogado
 * Formulario (validación/sanitización), WhatsApp, navegación.
 *
 * NOTAS DE SEGURIDAD PARA PRODUCCIÓN
 * ----------------------------------
 * 1. HTTPS obligatorio en todo el sitio (formulario + enlaces).
 * 2. Backend: validar y sanitizar TODOS los campos otra vez
 *    (nunca confiar solo en el cliente). Rechazar longitudes
 *    excesivas, tipos incorrectos y HTML/scripts.
 * 3. Rate limiting en el endpoint de contacto (p. ej. 5 req/IP/hora).
 * 4. Honeypot + valorar reCAPTCHA v3 / hCaptcha en el servidor.
 * 5. No almacenar PII en localStorage/sessionStorage.
 * 6. No exponer API keys, tokens ni endpoints internos aquí.
 * 7. Escapar cualquier dato de usuario antes de insertarlo en el DOM
 *    (usar textContent; nunca innerHTML con input crudo).
 * 8. Cabeceras recomendadas en el servidor web:
 *    - Content-Security-Policy (restringir scripts/estilos/fuentes)
 *    - X-Frame-Options: DENY (o CSP frame-ancestors)
 *    - X-Content-Type-Options: nosniff
 *    - Strict-Transport-Security: max-age=31536000; includeSubDomains
 *    - Referrer-Policy: strict-origin-when-cross-origin
 * 9. Cifrado en tránsito (TLS) y en reposo en BD del backend.
 * 10. Logs de acceso al formulario sin volcar datos sensibles.
 * ============================================================
 */

(function () {
  "use strict";

  var WA_NUMBER = "54343155118321"; // AR: 0343 155 118321 → E.164 sin +
  var WA_PREFILL =
    "Hola, me gustaría consultar sobre un asunto legal. ¿Podemos hablar?";

  /* —— Helpers de sanitización / XSS —— */
  function stripTags(str) {
    return String(str == null ? "" : str).replace(/<[^>]*>/g, "");
  }

  function normalizeWhitespace(str) {
    return String(str).replace(/\s+/g, " ").trim();
  }

  function sanitizeText(str, maxLen) {
    var clean = normalizeWhitespace(stripTags(str));
    if (maxLen && clean.length > maxLen) {
      clean = clean.slice(0, maxLen);
    }
    return clean;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function isValidEmail(email) {
    // Validación básica; el backend debe aplicar RFC estricto + DNS si aplica
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email);
  }

  function isValidPhone(phone) {
    var digits = phone.replace(/\D/g, "");
    return digits.length >= 8 && digits.length <= 15;
  }

  function setStatus(el, message, state) {
    if (!el) return;
    // textContent evita XSS al mostrar mensajes
    el.textContent = message;
    el.setAttribute("data-state", state || "");
    el.setAttribute("role", "status");
  }

  function markInvalid(field, message) {
    field.classList.add("is-invalid");
    field.setAttribute("aria-invalid", "true");
    var feedback = field.parentElement.querySelector(".invalid-feedback");
    if (feedback) {
      feedback.textContent = message;
    }
  }

  function clearInvalid(field) {
    field.classList.remove("is-invalid");
    field.removeAttribute("aria-invalid");
  }

  /* —— Navbar: cerrar menú mobile al navegar —— */
  function initNav() {
    var nav = document.getElementById("mainNav");
    if (!nav || typeof bootstrap === "undefined") return;

    var collapseEl = document.getElementById("navbarMain");
    if (!collapseEl) return;

    var bsCollapse = bootstrap.Collapse.getOrCreateInstance(collapseEl, {
      toggle: false,
    });

    nav.querySelectorAll("a.nav-link, .dropdown-item").forEach(function (link) {
      link.addEventListener("click", function () {
        if (window.matchMedia("(max-width: 991.98px)").matches && collapseEl.classList.contains("show")) {
          bsCollapse.hide();
        }
      });
    });
  }

  /* —— Formulario de contacto —— */
  function initContactForm() {
    var form = document.getElementById("contactForm");
    if (!form) return;

    var statusEl = document.getElementById("formStatus");
    var submitBtn = form.querySelector('[type="submit"]');

    form.addEventListener("submit", function (e) {
      e.preventDefault();

      var name = form.elements.namedItem("name");
      var email = form.elements.namedItem("email");
      var phone = form.elements.namedItem("phone");
      var service = form.elements.namedItem("service");
      var message = form.elements.namedItem("message");
      var privacy = form.elements.namedItem("privacy");
      var honeypot = form.elements.namedItem("company_website");

      [name, email, phone, service, message].forEach(function (f) {
        if (f) clearInvalid(f);
      });
      setStatus(statusEl, "", "");

      // Anti-bot: si el honeypot tiene valor, abortar en silencio
      if (honeypot && sanitizeText(honeypot.value, 200) !== "") {
        setStatus(statusEl, "Mensaje enviado. Nos pondremos en contacto pronto.", "success");
        form.reset();
        return;
      }

      var errors = 0;

      var nameVal = sanitizeText(name.value, 80);
      if (nameVal.length < 2) {
        markInvalid(name, "Indicá tu nombre completo (mín. 2 caracteres).");
        errors++;
      }

      var emailVal = sanitizeText(email.value, 120).toLowerCase();
      if (!isValidEmail(emailVal)) {
        markInvalid(email, "Ingresá un correo electrónico válido.");
        errors++;
      }

      var phoneVal = sanitizeText(phone.value, 30);
      if (phoneVal && !isValidPhone(phoneVal)) {
        markInvalid(phone, "Ingresá un teléfono válido (8–15 dígitos).");
        errors++;
      }

      var serviceVal = sanitizeText(service.value, 80);
      if (!serviceVal) {
        markInvalid(service, "Seleccioná cómo podemos ayudarte.");
        errors++;
      }

      var messageVal = sanitizeText(message.value, 2000);
      if (messageVal.length < 10) {
        markInvalid(message, "Contanos un poco más (mín. 10 caracteres).");
        errors++;
      }

      if (!privacy.checked) {
        markInvalid(privacy, "Debés aceptar la Política de Privacidad.");
        privacy.setAttribute("aria-invalid", "true");
        errors++;
      } else {
        privacy.removeAttribute("aria-invalid");
        privacy.classList.remove("is-invalid");
      }

      if (errors > 0) {
        setStatus(statusEl, "Revisá los campos marcados e intentá de nuevo.", "error");
        var firstInvalid = form.querySelector(".is-invalid");
        if (firstInvalid) firstInvalid.focus();
        return;
      }

      /*
       * BACKEND (obligatorio en producción):
       * POST HTTPS a un endpoint propio, p. ej. /api/contact
       * Body JSON: { name, email, phone, service, message, privacyAccepted: true }
       * Server-side: re-validar, sanitizar, rate-limit, store cifrado, notificar.
       * Nunca enviar a un webhook con secretos embebidos en este JS.
       *
       * Demo frontend: abrimos mailto solo como fallback local (sin persistir datos).
       */
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.setAttribute("aria-busy", "true");
      }

      var subject = "Consulta web — " + serviceVal;
      var body =
        "Nombre: " + nameVal + "\n" +
        "Email: " + emailVal + "\n" +
        "Teléfono: " + (phoneVal || "(no indicado)") + "\n" +
        "Servicio: " + serviceVal + "\n\n" +
        messageVal;

      // Fallback de demostración (reemplazar por fetch HTTPS al backend)
      var mailto =
        "mailto:exequielmarega@gmail.com" +
        "?subject=" + encodeURIComponent(subject) +
        "&body=" + encodeURIComponent(body);

      window.location.href = mailto;

      setStatus(
        statusEl,
        "Gracias, " + nameVal + ". Si no se abrió tu cliente de correo, escribinos a exequielmarega@gmail.com.",
        "success"
      );

      form.reset();

      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.removeAttribute("aria-busy");
      }

      // escapeHtml disponible si en el futuro se usa HTML; preferir textContent
      void escapeHtml;
    });

    form.querySelectorAll("input, select, textarea").forEach(function (field) {
      field.addEventListener("input", function () {
        clearInvalid(field);
      });
    });
  }

  /* —— WhatsApp widget —— */
  function initWhatsApp() {
    var root = document.getElementById("waWidget");
    if (!root) return;

    var btn = root.querySelector(".em-wa-btn");
    var panel = root.querySelector(".em-wa-panel");
    var closeBtn = root.querySelector(".em-wa-close");
    var openChat = root.querySelector(".em-wa-open");

    function setOpen(open) {
      if (!panel || !btn) return;
      panel.classList.toggle("is-open", open);
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      panel.setAttribute("aria-hidden", open ? "false" : "true");
    }

    if (btn) {
      btn.addEventListener("click", function () {
        setOpen(!panel.classList.contains("is-open"));
      });
    }

    if (closeBtn) {
      closeBtn.addEventListener("click", function () {
        setOpen(false);
        btn.focus();
      });
    }

    if (openChat) {
      openChat.addEventListener("click", function (e) {
        e.preventDefault();
        var url =
          "https://wa.me/" +
          WA_NUMBER +
          "?text=" +
          encodeURIComponent(WA_PREFILL);
        window.open(url, "_blank", "noopener,noreferrer");
      });
    }

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") setOpen(false);
    });
  }

  /* —— Año copyright —— */
  function initYear() {
    var el = document.getElementById("yearNow");
    if (el) el.textContent = String(new Date().getFullYear());
  }

  /* —— Self-check (abrí index.html?selfcheck=1) —— */
  function runSelfCheck() {
    var ok =
      sanitizeText("  <b>Ana</b>  ", 10) === "Ana" &&
      isValidEmail("exequielmarega@gmail.com") === true &&
      isValidEmail("malo@") === false &&
      isValidPhone("0343 155 118321") === true &&
      escapeHtml("<script>") === "&lt;script&gt;";
    console.assert(ok, "form helpers self-check failed");
    if (ok) console.info("[selfcheck] OK");
  }

  document.addEventListener("DOMContentLoaded", function () {
    initNav();
    initContactForm();
    initWhatsApp();
    initYear();
    if (/[?&]selfcheck=1(?:&|$)/.test(location.search)) {
      runSelfCheck();
    }
  });
})();
