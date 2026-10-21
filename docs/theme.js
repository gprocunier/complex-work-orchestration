/* Loaded before styles: apply a saved choice before the page paints.
 * Native radio choices and CSS keep System/Light/Dark usable without scripts.
 * Embedded SVG media queries inherit the selected CSS color-scheme.
 */
(() => {
  const key = "cwo-color-theme";
  const root = document.documentElement;
  const normalize = (value) => ["light", "dark"].includes(value) ? value : "system";
  let preference = "system";
  try { preference = normalize(window.localStorage.getItem(key)); } catch (_) { /* storage may be disabled */ }
  root.dataset.theme = preference;

  const enhance = () => {
    const choices = [...document.querySelectorAll('#site-theme input[type="radio"]')];
    if (!choices.length) return;
    const apply = (value) => {
      preference = normalize(value);
      // Complete every native choice before observers see the root change.
      choices.forEach((choice) => { choice.checked = choice.value === preference; });
      root.dataset.theme = preference;
    };
    choices.forEach((choice) => {
      choice.addEventListener("change", () => {
        if (!choice.checked) return;
        apply(choice.value);
        try {
          if (preference === "system") window.localStorage.removeItem(key);
          else window.localStorage.setItem(key, preference);
        } catch (_) { /* the current page choice remains usable */ }
      });
    });
    window.addEventListener("storage", (event) => {
      if (event.key !== key && event.key !== null) return;
      // Ignore same-named sessionStorage events; never echo a storage write.
      try { if (event.storageArea !== window.localStorage) return; } catch (_) { return; }
      apply(event.key === null ? "system" : event.newValue);
    });
    apply(preference);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", enhance, {once: true});
  else enhance();
})();
