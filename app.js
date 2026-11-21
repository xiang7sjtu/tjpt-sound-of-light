const ACCESS_MAGIC = "TJPT-ACCESS-V1";
const PAYLOAD_MAGIC = "TJPT";
const PAYLOAD_VERSION = 1;

const gate = document.querySelector("#gate");
const library = document.querySelector("#library");
const accessForm = document.querySelector("#accessForm");
const passwordInput = document.querySelector("#password");
const accessMessage = document.querySelector("#accessMessage");
const unlockButton = document.querySelector("#unlockButton");
const revealPasswordButton = document.querySelector("#revealPassword");
const lockButton = document.querySelector("#lockButton");
const loadVideoButton = document.querySelector("#loadVideoButton");
const video = document.querySelector("#video");
const videoPlaceholder = document.querySelector("#videoPlaceholder");
const videoProgress = document.querySelector("#videoProgress");
const videoProgressBar = videoProgress.querySelector("span");
const videoMessage = document.querySelector("#videoMessage");
const previewScriptButton = document.querySelector("#previewScriptButton");
const scriptPreview = document.querySelector("#scriptPreview");
const scriptNote = document.querySelector("#scriptNote");
const resourceList = document.querySelector("#resourceList");

const state = {
  manifest: null,
  key: null,
  objectUrls: new Set(),
};

function bytesFromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function formatBytes(value) {
  if (value >= 1024 * 1024) {
    return `${(value / 1024 / 1024).toFixed(1)} MB`;
  }
  return `${Math.max(1, Math.round(value / 1024))} KB`;
}

async function getManifest() {
  if (state.manifest) {
    return state.manifest;
  }
  const response = await fetch("./manifest.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("无法读取资料清单");
  }
  state.manifest = await response.json();
  return state.manifest;
}

function findAsset(manifest, id) {
  const asset = manifest.assets.find((item) => item.id === id);
  if (!asset) {
    throw new Error(`缺少资料：${id}`);
  }
  return asset;
}

async function deriveKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

function parsePayload(buffer) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 33) {
    throw new Error("加密资料格式不完整");
  }
  const magic = new TextDecoder().decode(bytes.slice(0, 4));
  if (magic !== PAYLOAD_MAGIC || bytes[4] !== PAYLOAD_VERSION) {
    throw new Error("加密资料版本不匹配");
  }
  const iv = bytes.slice(5, 17);
  const tag = bytes.slice(-16);
  const ciphertext = bytes.slice(17, -16);
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);
  return { iv, sealed };
}

async function decryptBuffer(buffer, key) {
  const { iv, sealed } = parsePayload(buffer);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    sealed,
  );
}

async function fetchEncryptedAsset(asset, onProgress) {
  const response = await fetch(`./assets/${asset.file}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`无法读取 ${asset.label}`);
  }
  const total = Number(response.headers.get("content-length")) || asset.encryptedBytes;
  if (!response.body || !onProgress) {
    return response.arrayBuffer();
  }

  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    chunks.push(value);
    received += value.length;
    onProgress(Math.min(1, received / total));
  }
  const output = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output.buffer;
}

async function decryptAsset(asset) {
  if (!state.key) {
    throw new Error("资料尚未解锁");
  }
  const encrypted = await fetchEncryptedAsset(asset);
  return decryptBuffer(encrypted, state.key);
}

function setAccessMessage(message, isError = true) {
  accessMessage.textContent = message;
  accessMessage.style.color = isError ? "var(--terracotta-dark)" : "var(--ink-soft)";
}

function setUnlocking(value) {
  unlockButton.disabled = value;
  unlockButton.querySelector("span").textContent = value ? "正在校验…" : "进入资料";
}

function showLibrary() {
  gate.hidden = true;
  library.hidden = false;
  accessForm.reset();
  accessMessage.textContent = "";
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function clearObjectUrls() {
  for (const url of state.objectUrls) {
    URL.revokeObjectURL(url);
  }
  state.objectUrls.clear();
}

function lockLibrary() {
  state.key = null;
  clearObjectUrls();
  video.pause();
  video.removeAttribute("src");
  video.load();
  video.hidden = true;
  videoPlaceholder.hidden = false;
  videoProgress.hidden = true;
  videoProgressBar.style.width = "0%";
  videoMessage.textContent = "";
  scriptPreview.hidden = true;
  scriptPreview.textContent = "";
  scriptNote.textContent = "可在解锁后预览或下载纯文本。";
  previewScriptButton.textContent = "预览";
  library.hidden = true;
  gate.hidden = false;
  setAccessMessage("");
  passwordInput.focus();
}

async function handleAccess(event) {
  event.preventDefault();
  const password = passwordInput.value;
  if (!password) {
    setAccessMessage("请输入访问密码。");
    passwordInput.focus();
    return;
  }

  setUnlocking(true);
  setAccessMessage("正在校验密码…", false);
  try {
    const manifest = await getManifest();
    const key = await deriveKey(
      password,
      bytesFromBase64(manifest.kdf.salt),
      manifest.kdf.iterations,
    );
    const checkAsset = findAsset(manifest, "check");
    const encryptedCheck = await fetchEncryptedAsset(checkAsset);
    const plainCheck = await decryptBuffer(encryptedCheck, key);
    const checkText = new TextDecoder().decode(plainCheck);
    if (checkText !== ACCESS_MAGIC) {
      throw new Error("密码不正确");
    }
    state.key = key;
    showLibrary();
    renderResources(manifest);
  } catch (error) {
    state.key = null;
    if (error?.name === "OperationError") {
      setAccessMessage("密码不正确，请重新输入。");
    } else {
      setAccessMessage(error?.message || "资料加载失败，请稍后重试。");
    }
  } finally {
    setUnlocking(false);
  }
}

function renderResources(manifest) {
  const resources = manifest.assets.filter((asset) => asset.download);
  resourceList.replaceChildren();
  for (const asset of resources) {
    const item = document.createElement("li");
    item.className = "resource-item";

    const copy = document.createElement("div");
    const label = document.createElement("strong");
    label.textContent = asset.label;
    const meta = document.createElement("span");
    meta.textContent = `${asset.description} · ${formatBytes(asset.plainBytes)}`;
    copy.append(label, meta);

    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "下载";
    button.addEventListener("click", () => downloadAsset(asset, button));
    item.append(copy, button);
    resourceList.append(item);
  }
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  state.objectUrls.add(url);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => {
    URL.revokeObjectURL(url);
    state.objectUrls.delete(url);
  }, 30000);
}

async function downloadAsset(asset, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "解密中";
  try {
    const plain = await decryptAsset(asset);
    saveBlob(new Blob([plain], { type: asset.mime }), asset.filename);
    button.textContent = "已下载";
    window.setTimeout(() => {
      button.textContent = original;
    }, 1800);
  } catch (error) {
    button.textContent = "失败";
    window.setTimeout(() => {
      button.textContent = original;
    }, 1800);
  } finally {
    button.disabled = false;
  }
}

async function loadVideo() {
  loadVideoButton.disabled = true;
  videoMessage.textContent = "正在读取加密视频…";
  videoProgress.hidden = false;
  videoProgressBar.style.width = "0%";
  try {
    const manifest = await getManifest();
    const asset = findAsset(manifest, "video");
    const encrypted = await fetchEncryptedAsset(asset, (ratio) => {
      videoProgressBar.style.width = `${Math.round(ratio * 100)}%`;
    });
    videoMessage.textContent = "正在解密…";
    const plain = await decryptBuffer(encrypted, state.key);
    const blob = new Blob([plain], { type: asset.mime });
    const url = URL.createObjectURL(blob);
    state.objectUrls.add(url);
    video.src = url;
    video.hidden = false;
    videoPlaceholder.hidden = true;
    video.load();
    try {
      await video.play();
    } catch {
      // The browser may require an extra click to start playback.
    }
  } catch (error) {
    videoMessage.textContent = error?.message || "视频载入失败，请重试。";
    videoProgress.hidden = true;
  } finally {
    loadVideoButton.disabled = false;
  }
}

async function toggleScriptPreview() {
  if (!scriptPreview.hidden) {
    scriptPreview.hidden = true;
    previewScriptButton.textContent = "预览";
    scriptNote.textContent = "可在解锁后预览或下载纯文本。";
    return;
  }

  previewScriptButton.disabled = true;
  previewScriptButton.textContent = "读取中";
  try {
    const manifest = await getManifest();
    const asset = findAsset(manifest, "script");
    const plain = await decryptAsset(asset);
    scriptPreview.textContent = new TextDecoder().decode(plain);
    scriptPreview.hidden = false;
    previewScriptButton.textContent = "收起";
    scriptNote.textContent = "当前版本为 AI 讲解稿，可用于重新配音或现场讲述。";
  } catch (error) {
    scriptNote.textContent = "文字稿读取失败，请重试。";
  } finally {
    previewScriptButton.disabled = false;
  }
}

revealPasswordButton.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  revealPasswordButton.setAttribute("aria-label", showing ? "显示密码" : "隐藏密码");
});

accessForm.addEventListener("submit", handleAccess);
lockButton.addEventListener("click", lockLibrary);
loadVideoButton.addEventListener("click", loadVideo);
previewScriptButton.addEventListener("click", toggleScriptPreview);

window.addEventListener("beforeunload", clearObjectUrls);
