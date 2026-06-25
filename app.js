const form = document.querySelector("#unlock-form");
const passwordInput = document.querySelector("#password");
const statusEl = document.querySelector("#status");
const gate = document.querySelector("#gate");
const docShell = document.querySelector("#doc-shell");
const content = document.querySelector("#content");
const docTitle = document.querySelector("#doc-title");
const docMeta = document.querySelector("#doc-meta");
const lockButton = document.querySelector("#lock-button");

let payloadPromise;

const textDecoder = new TextDecoder();

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function loadPayload() {
  if (!payloadPromise) {
    payloadPromise = fetch("./payload.json", { cache: "no-store" }).then((res) => {
      if (!res.ok) {
        throw new Error("Unable to load encrypted payload.");
      }
      return res.json();
    });
  }
  return payloadPromise;
}

async function deriveKey(password, salt, iterations) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptPayload(password) {
  const encrypted = await loadPayload();
  const salt = fromBase64(encrypted.salt);
  const iv = fromBase64(encrypted.iv);
  const ciphertext = fromBase64(encrypted.ciphertext);
  const key = await deriveKey(password, salt, encrypted.iterations);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  return JSON.parse(textDecoder.decode(plaintext));
}

async function renderMermaid() {
  const nodes = content.querySelectorAll(".mermaid");
  if (!nodes.length) return;

  try {
    const mermaidModule = await import("https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs");
    mermaidModule.default.initialize({ startOnLoad: false, theme: "neutral", securityLevel: "strict" });
    await mermaidModule.default.run({ nodes });
  } catch {
    nodes.forEach((node) => {
      node.dataset.renderError = "Mermaid rendering unavailable.";
    });
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  statusEl.textContent = "Decrypting...";

  try {
    const unlocked = await decryptPayload(passwordInput.value);
    docTitle.textContent = unlocked.title;
    docMeta.textContent = `Built ${unlocked.builtAt} from source SHA-256 ${unlocked.sourceSha256}.`;
    content.innerHTML = unlocked.html;
    gate.hidden = true;
    docShell.hidden = false;
    passwordInput.value = "";
    await renderMermaid();
  } catch {
    statusEl.textContent = "Wrong password or corrupted payload.";
  } finally {
    button.disabled = false;
  }
});

lockButton.addEventListener("click", () => {
  content.replaceChildren();
  docShell.hidden = true;
  gate.hidden = false;
  statusEl.textContent = "";
  passwordInput.focus();
});
