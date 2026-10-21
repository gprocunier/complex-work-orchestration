"use strict";
// Native disclosure works without JavaScript; this only sets viewport defaults.
const contents = document.querySelector(".reading-layout > .contents");
if (contents) {
  const wide = window.matchMedia("(min-width: 64rem)");
  const sync = () => {
    if (!wide.matches && contents.contains(document.activeElement)) {
      contents.querySelector("summary").focus();
    }
    contents.open = wide.matches;
  };
  wide.addEventListener("change", sync);
  sync();
}

// Native disclosure stays usable without JavaScript; keep every destination.
const menu = document.querySelector(".site-menu");
if (menu) {
  const desktop = window.matchMedia("(min-width: 58rem)");
  const sync = () => {
    if (!desktop.matches && menu.contains(document.activeElement)) {
      menu.querySelector("summary").focus();
    }
    menu.open = desktop.matches;
  };
  desktop.addEventListener("change", sync);
  sync();
}

// Read the entire code node, never a visually clipped or summarized prompt.
document.querySelectorAll("pre.prompt").forEach((block, index) => {
  const code = block.querySelector("code");
  if (!code) return;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy-prompt";
  button.textContent = "Copy complete prompt";
  const status = document.createElement("p");
  status.className = "copy-status";
  status.id = `prompt-copy-status-${index}`;
  status.setAttribute("aria-live", "polite");
  button.setAttribute("aria-describedby", status.id);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      status.textContent = "Complete prompt copied.";
    } catch {
      // Permissions, insecure contexts and synchronous failures all retain a
      // selectable fallback. Do not claim clipboard success on rejection.
      const selection = window.getSelection();
      if (selection) {
        const range = document.createRange();
        range.selectNodeContents(code);
        selection.removeAllRanges();
        selection.addRange(range);
      }
      status.textContent = "Copy unavailable. Select the complete prompt and copy it manually.";
    }
  });
  block.before(button);
  block.after(status);
});

// A native disclosure is the fallback: Enter/Space and touch need no JS.
// Hover is an enhancement, never the only way to read the zero-trust note.
document.querySelectorAll(".review-explainer").forEach((details) => {
  const summary = details.querySelector("summary");
  const zone = details.parentElement;
  const aura = zone.parentElement.querySelector(".review-aura");
  let hoverOpened = false;
  let closeTimer;
  const cancelClose = () => window.clearTimeout(closeTimer);
  const close = () => {
    cancelClose();
    hoverOpened = false;
    zone.classList.add("is-dismissed");
    details.open = false;
  };
  zone.addEventListener("pointerenter", (event) => {
    if (event.pointerType !== "mouse") return;
    cancelClose();
    zone.classList.remove("is-dismissed");
    if (!details.open) {
      hoverOpened = true;
      details.open = true;
    }
  });
  zone.addEventListener("pointerleave", () => {
    zone.classList.remove("is-dismissed");
    if (!hoverOpened) return;
    cancelClose();
    closeTimer = window.setTimeout(() => {
      if (!zone.contains(document.activeElement)) close();
    }, 250);
  });
  // The first click pins a hover-open note instead of immediately closing it.
  // Later clicks, keyboard activation and touch keep native details behavior.
  summary.addEventListener("click", (event) => {
    if (hoverOpened && details.open) {
      event.preventDefault();
      hoverOpened = false;
    }
  });
  zone.addEventListener("focusin", cancelClose);
  zone.addEventListener("focusout", (event) => {
    if (!zone.contains(event.relatedTarget)) close();
  });
  zone.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !details.open) return;
    event.preventDefault();
    summary.focus();
    close();
  });
  document.addEventListener("pointerdown", (event) => {
    if (!zone.contains(event.target)) {
      if (zone.contains(document.activeElement)) summary.focus();
      close();
    }
  });

  const positionNote = () => {
    if (!details.open || !window.matchMedia("(min-width: 64rem) and (min-height: 40rem)").matches) return;
    zone.classList.remove("is-above");
    const anchor = summary.getBoundingClientRect();
    const note = zone.querySelector(".review-popover").getBoundingClientRect();
    const below = window.innerHeight - anchor.bottom - 32;
    if (below < note.height && anchor.top > below) zone.classList.add("is-above");
  };
  details.addEventListener("toggle", positionNote);
  window.addEventListener("resize", positionNote);
  window.addEventListener("scroll", positionNote, {passive: true});
  zone.classList.add("is-enhanced");

  // Two gentle pulses begin when Review comes into view, then settle to a
  // static glow. Reduced-motion CSS disables even that short animation.
  if (aura) {
    if ("IntersectionObserver" in window) {
      const observer = new window.IntersectionObserver((entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          aura.classList.add("is-visible");
          observer.disconnect();
        }
      });
      observer.observe(aura);
    } else {
      aura.classList.add("is-visible");
    }
  }
});
