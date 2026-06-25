const form = document.querySelector("#unlock-form");
const passwordInput = document.querySelector("#password");
const statusEl = document.querySelector("#status");
const gate = document.querySelector("#gate");
const docShell = document.querySelector("#doc-shell");
const content = document.querySelector("#content");
const docTitle = document.querySelector("#doc-title");
const docMeta = document.querySelector("#doc-meta");
const lockButton = document.querySelector("#lock-button");
const toc = document.querySelector("#toc");
const tocPanel = document.querySelector(".toc-panel");

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

function buildTableOfContents() {
  const headings = Array.from(content.querySelectorAll("h2, h3"));
  const usedIds = new Map();
  toc.replaceChildren();

  if (!headings.length) {
    tocPanel.hidden = true;
    return;
  }

  tocPanel.hidden = false;
  const list = document.createElement("ol");
  list.className = "toc-list";

  headings.forEach((heading, index) => {
    const base = slugify(heading.textContent) || `section-${index + 1}`;
    const count = usedIds.get(base) || 0;
    usedIds.set(base, count + 1);
    heading.id = count ? `${base}-${count + 1}` : base;

    const item = document.createElement("li");
    item.className = `toc-item toc-${heading.tagName.toLowerCase()}`;

    const link = document.createElement("a");
    link.href = `#${heading.id}`;
    link.textContent = heading.textContent;
    item.append(link);
    list.append(item);
  });

  toc.append(list);
}

function slugify(value) {
  return value
    .toLowerCase()
    .trim()
    .replace(/`/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
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
    buildTableOfContents();
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
  toc.replaceChildren();
  docShell.hidden = true;
  gate.hidden = false;
  statusEl.textContent = "";
  passwordInput.focus();
});
