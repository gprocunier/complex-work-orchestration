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
