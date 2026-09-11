"use strict";

const MAX_IMAGE_BYTES_BEFORE_DOWNSCALE = 3.5 * 1024 * 1024;
const MAX_IMAGE_DIMENSION = 2000;
const JPEG_QUALITY = 0.85;
const ACCEPTED_IMAGE_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);
const LOADING_MESSAGES = [
  "Reading the message…",
  "Checking scam patterns…",
  "Almost done…",
];

const form = document.querySelector("#analysis-form");
const textInput = document.querySelector("#message-text");
const characterCount = document.querySelector("#character-count");
const imageInput = document.querySelector("#image-input");
const dropZone = document.querySelector("#drop-zone");
const imagePreview = document.querySelector("#image-preview");
const previewImage = document.querySelector("#preview-image");
const previewName = document.querySelector("#preview-name");
const previewDetails = document.querySelector("#preview-details");
const removeImageButton = document.querySelector("#remove-image");
const submitButton = document.querySelector("#submit-button");
const buttonLabel = document.querySelector("#button-label");
const loadingStatus = document.querySelector("#loading-status");
const formError = document.querySelector("#form-error");
const resultRegion = document.querySelector("#result-region");
const resultCard = document.querySelector("#result-card");
const resultContent = document.querySelector("#result-content");

let selectedImage = null;
let loadingTimer = null;
let isSubmitting = false;

function formatBytes(bytes) {
  if (bytes < 1024 * 1024) {
    return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fitWithinMaxDimension(width, height, maxDimension = MAX_IMAGE_DIMENSION) {
  const scale = Math.min(1, maxDimension / Math.max(width, height));
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
  };
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

function clearError() {
  formError.textContent = "";
  formError.hidden = true;
}

function updateSubmitState() {
  const hasInput = textInput.value.trim().length > 0 || selectedImage !== null;
  submitButton.disabled = !hasInput || isSubmitting;
}

function updateCharacterCount() {
  characterCount.textContent = `${textInput.value.length.toLocaleString()} / 10,000`;
  updateSubmitState();
}

function loadImage(blob) {
  return new Promise((resolve, reject) => {
    const objectUrl = URL.createObjectURL(blob);
    const image = new Image();
    image.onload = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(image);
    };
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error("The image could not be read."));
    };
    image.src = objectUrl;
  });
}

function canvasToBlob(canvas) {
  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => {
        if (blob) {
          resolve(blob);
        } else {
          reject(new Error("The image could not be prepared."));
        }
      },
      "image/jpeg",
      JPEG_QUALITY,
    );
  });
}

async function downscaleImage(file) {
  const image = await loadImage(file);
  const size = fitWithinMaxDimension(image.naturalWidth, image.naturalHeight);
  const canvas = document.createElement("canvas");
  canvas.width = size.width;
  canvas.height = size.height;
  const context = canvas.getContext("2d");
  if (!context) {
    throw new Error("Image processing is not supported in this browser.");
  }
  context.drawImage(image, 0, 0, size.width, size.height);
  return canvasToBlob(canvas);
}

function blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1]);
    reader.onerror = () => reject(new Error("The image could not be prepared."));
    reader.readAsDataURL(blob);
  });
}

function imageFormatFromType(type) {
  if (type === "image/png") return "png";
  if (type === "image/webp") return "webp";
  return "jpeg";
}

async function prepareImage(file) {
  if (!ACCEPTED_IMAGE_TYPES.has(file.type)) {
    throw new Error("Choose a PNG, JPEG, or WebP screenshot.");
  }

  const wasDownscaled = file.size > MAX_IMAGE_BYTES_BEFORE_DOWNSCALE;
  const blob = wasDownscaled ? await downscaleImage(file) : file;
  if (blob.size > 4 * 1024 * 1024) {
    throw new Error("This screenshot is still too large. Try a smaller image.");
  }

  return {
    base64: await blobToBase64(blob),
    blob,
    fileName: file.name || "Pasted screenshot",
    format: imageFormatFromType(blob.type),
    originalSize: file.size,
    previewUrl: URL.createObjectURL(blob),
    wasDownscaled,
  };
}

function clearSelectedImage() {
  if (selectedImage?.previewUrl) {
    URL.revokeObjectURL(selectedImage.previewUrl);
  }
  selectedImage = null;
  imageInput.value = "";
  previewImage.removeAttribute("src");
  imagePreview.hidden = true;
  updateSubmitState();
}

async function handleImage(file) {
  clearError();
  try {
    const prepared = await prepareImage(file);
    clearSelectedImage();
    selectedImage = prepared;
    previewImage.src = prepared.previewUrl;
    previewName.textContent = prepared.fileName;
    previewDetails.textContent = prepared.wasDownscaled
      ? `${formatBytes(prepared.originalSize)} compressed to ${formatBytes(prepared.blob.size)}`
      : formatBytes(prepared.blob.size);
    imagePreview.hidden = false;
  } catch (error) {
    clearSelectedImage();
    showError(error instanceof Error ? error.message : "The screenshot could not be added.");
  }
  updateSubmitState();
}

function startLoading() {
  isSubmitting = true;
  updateSubmitState();
  submitButton.classList.add("is-loading");
  buttonLabel.textContent = "Analyzing…";
  loadingStatus.hidden = false;
  let messageIndex = 0;
  loadingStatus.textContent = LOADING_MESSAGES[messageIndex];
  loadingTimer = window.setInterval(() => {
    messageIndex = (messageIndex + 1) % LOADING_MESSAGES.length;
    loadingStatus.textContent = LOADING_MESSAGES[messageIndex];
  }, 1800);
}

function stopLoading() {
  if (loadingTimer) {
    window.clearInterval(loadingTimer);
    loadingTimer = null;
  }
  isSubmitting = false;
  submitButton.classList.remove("is-loading");
  buttonLabel.textContent = "Check this message";
  loadingStatus.hidden = true;
  updateSubmitState();
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function humanize(value) {
  return String(value || "Warning sign").replace(/[_-]+/g, " ");
}

function verdictPresentation(verdict) {
  const presentations = {
    scam: { label: "SCAM", theme: "verdict-danger" },
    likely_scam: { label: "LIKELY SCAM", theme: "verdict-danger" },
    suspicious: { label: "SUSPICIOUS — VERIFY FIRST", theme: "verdict-warning" },
    likely_legitimate: { label: "LOOKS LEGITIMATE", theme: "verdict-success" },
    insufficient_content: { label: "NOT ENOUGH TO JUDGE", theme: "verdict-neutral" },
  };
  return presentations[verdict] || presentations.insufficient_content;
}

function createResultSection(title) {
  const section = element("section", "result-section");
  section.append(element("h3", "", title));
  return section;
}

function renderResult(result) {
  const presentation = verdictPresentation(result.verdict);
  resultCard.className = `result-card ${presentation.theme}`;
  resultContent.replaceChildren();

  if (result.demo_mode === true) {
    resultContent.append(
      element(
        "div",
        "demo-banner",
        "Demo result — the AI engine is being activated. This is sample output, not a real analysis.",
      ),
    );
  }

  resultContent.append(element("p", "verdict-label", presentation.label));
  resultContent.append(
    element("h2", "result-headline", result.headline || "Analysis complete."),
  );

  if (result.scam_family_label) {
    resultContent.append(element("span", "family-badge", result.scam_family_label));
  }

  const confidence = Math.max(0, Math.min(100, Number(result.confidence) || 0));
  const confidenceRow = element("div", "confidence-row");
  confidenceRow.append(element("span", "", "Confidence"));
  confidenceRow.append(element("span", "", `${confidence}%`));
  resultContent.append(confidenceRow);
  const meter = element("div", "confidence-meter");
  meter.setAttribute("role", "meter");
  meter.setAttribute("aria-label", "Analysis confidence");
  meter.setAttribute("aria-valuemin", "0");
  meter.setAttribute("aria-valuemax", "100");
  meter.setAttribute("aria-valuenow", String(confidence));
  const meterFill = element("span");
  meterFill.style.width = `${confidence}%`;
  meter.append(meterFill);
  resultContent.append(meter);

  const redFlags = Array.isArray(result.red_flags) ? result.red_flags : [];
  const flagSection = createResultSection("Red flags found");
  const flagList = element("ul", "flag-list");
  if (redFlags.length === 0) {
    flagList.append(element("li", "flag-item", "No specific red flags were identified."));
  } else {
    redFlags.forEach((flag) => {
      const item = element("li", "flag-item");
      item.append(element("strong", "flag-name", humanize(flag.type)));
      if (flag.evidence) {
        item.append(element("blockquote", "", `“${flag.evidence}”`));
      }
      if (flag.explanation) {
        item.append(element("p", "", flag.explanation));
      }
      flagList.append(item);
    });
  }
  flagSection.append(flagList);
  resultContent.append(flagSection);

  const actions = Array.isArray(result.what_to_do) ? result.what_to_do : [];
  if (actions.length > 0) {
    const actionSection = createResultSection("What you should do");
    const actionList = element("ul", "action-list");
    actions.forEach((action) => actionList.append(element("li", "", action)));
    actionSection.append(actionList);
    resultContent.append(actionSection);
  }

  if (result.what_scammer_wants) {
    const goal = element("p", "scammer-goal");
    goal.append(element("strong", "", "What the scammer wants: "));
    goal.append(document.createTextNode(result.what_scammer_wants));
    resultContent.append(goal);
  }

  resultRegion.hidden = false;
  resultRegion.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function submitAnalysis(event) {
  event.preventDefault();
  clearError();
  resultRegion.hidden = true;

  const text = textInput.value.trim();
  if (!text && !selectedImage) {
    showError("Add a message or screenshot before checking it.");
    return;
  }

  const payload = {};
  if (text) payload.text = text;
  if (selectedImage) {
    payload.image_base64 = selectedImage.base64;
    payload.image_format = selectedImage.format;
  }

  startLoading();
  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (response.status === 400) {
      showError("Please check your message or screenshot and try again.");
      return;
    }
    if (!response.ok) {
      showError("Analysis failed — please try again in a moment.");
      return;
    }

    renderResult(await response.json());
  } catch {
    showError("Analysis failed — please try again in a moment.");
  } finally {
    stopLoading();
  }
}

textInput.addEventListener("input", updateCharacterCount);
form.addEventListener("submit", submitAnalysis);
imageInput.addEventListener("change", () => {
  if (imageInput.files?.[0]) handleImage(imageInput.files[0]);
});
removeImageButton.addEventListener("click", clearSelectedImage);

dropZone.addEventListener("click", (event) => {
  if (event.target !== imageInput) imageInput.click();
});
dropZone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    imageInput.click();
  }
});

["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
  });
});

dropZone.addEventListener("drop", (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (file) handleImage(file);
});

document.addEventListener("paste", (event) => {
  const imageItem = Array.from(event.clipboardData?.items || []).find((item) =>
    item.type.startsWith("image/"),
  );
  const file = imageItem?.getAsFile();
  if (file) handleImage(file);
});

updateCharacterCount();

window.ScamBusterImageSizing = Object.freeze({ fitWithinMaxDimension });
