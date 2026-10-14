// PhishGuard - simulasi edukatif di browser.
// Catatan: ini bukan layanan deteksi phishing sungguhan dan tidak memeriksa reputasi domain.

document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector(".url-form");
  const input = document.querySelector("#url-input");
  const result = document.querySelector(".scan-result");
  const resultTitle = result?.querySelector("h3");
  const resultText = result?.querySelector(".scan-result__content > p");
  const checkedUrl = result?.querySelector(".checked-url");
  const reasonsList = result?.querySelector(".detection-reasons ul");
  const historyList = document.querySelector(".history-list");
  const clearButton = document.querySelector(".clear-history");
  const submitButton = document.querySelector(".url-submit");
  const stats = {
    total: document.querySelector(".stat-card--total strong"),
    safe: document.querySelector(".stat-card--safe strong"),
    warning: document.querySelector(".stat-card--warning strong"),
    danger: document.querySelector(".stat-card--danger strong")
  };

  let history = [];
  let counts = { total: 0, safe: 0, warning: 0, danger: 0 };

  function iconSvg(type = "check") {
    const paths = {
      check: '<path d="m5 12 4 4L19 6"></path>',
      warning: '<path d="M12 4 3 20h18L12 4Z"></path><path d="M12 9v4m0 3h.01"></path>',
      danger: '<circle cx="12" cy="12" r="9"></circle><path d="m9 9 6 6m0-6-6 6"></path>'
    };
    return `<svg aria-hidden="true" class="icon" fill="none" height="18" viewBox="0 0 24 24" width="18">${paths[type] || paths.check}</svg>`;
  }

  function assessUrl(raw) {
    let parsed;
    try {
      parsed = new URL(raw.includes("://") ? raw : `https://${raw}`);
    } catch {
      return {
        status: "warning",
        title: "Format URL tidak valid",
        description: "Alamat yang dimasukkan belum memiliki format URL yang dapat dibaca. Periksa kembali penulisannya.",
        reasons: ["Pastikan alamat memiliki nama domain yang valid."]
      };
    }

    const host = parsed.hostname.toLowerCase();
    const full = `${parsed.hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
    const reasons = [];
    let risk = "safe";

    if (parsed.protocol !== "https:") {
      risk = "warning";
      reasons.push("URL tidak menggunakan protokol HTTPS.");
    } else {
      reasons.push("URL menggunakan protokol HTTPS.");
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      risk = "danger";
      reasons.push("Alamat menggunakan IP langsung, yang patut diperiksa lebih lanjut.");
    }

    if (host.includes("xn--")) {
      risk = "danger";
      reasons.push("Domain mengandung format Punycode yang dapat menyamarkan karakter.");
    }

    if (/@/.test(parsed.href)) {
      risk = "danger";
      reasons.push("URL mengandung tanda @ yang dapat membingungkan tujuan alamat.");
    }

    if (/(login|verify|account|password|secure|update|gift|prize|wallet|banking)/i.test(full)) {
      if (risk !== "danger") risk = "warning";
      reasons.push("URL mengandung kata kunci yang sering muncul pada tautan yang perlu diperiksa.");
    }

    if ((host.match(/\./g) || []).length >= 4 || host.length > 55) {
      if (risk !== "danger") risk = "warning";
      reasons.push("Struktur domain cukup panjang atau memiliki banyak subdomain.");
    }

    if (parsed.protocol === "http:" && risk === "safe") risk = "warning";
    if (reasons.length === 1) reasons.push("Tidak ditemukan pola sederhana lain pada pemeriksaan demo.");

    const descriptions = {
      safe: {
        title: "Tidak Ada Indikasi (Demo)",
        description: "Simulasi tidak menemukan pola mencurigakan umum pada URL ini. Ini bukan jaminan bahwa situs aman."
      },
      warning: {
        title: "Perlu Diperiksa (Demo)",
        description: "Simulasi menemukan satu atau lebih pola yang perlu diperiksa. Jangan masukkan data sensitif sebelum memastikan alamat situs."
      },
      danger: {
        title: "Indikasi Mencurigakan (Demo)",
        description: "Simulasi menemukan pola yang patut diwaspadai. Hindari memasukkan kata sandi, PIN, atau OTP."
      }
    };

    return { status: risk, ...descriptions[risk], reasons };
  }

  function updateResult(url, assessment) {
    if (!result) return;
    result.className = `scan-result scan-result--${assessment.status}`;
    if (resultTitle) resultTitle.textContent = assessment.title;
    if (resultText) resultText.textContent = assessment.description;
    if (checkedUrl) checkedUrl.textContent = url;
    if (reasonsList) {
      reasonsList.innerHTML = "";
      assessment.reasons.forEach(reason => {
        const li = document.createElement("li");
        li.innerHTML = `${iconSvg(assessment.status === "safe" ? "check" : "warning")}<span></span>`;
        li.querySelector("span").textContent = reason;
        reasonsList.appendChild(li);
      });
    }
  }

  function renderHistory() {
    if (!historyList) return;
    historyList.querySelectorAll(".history-row, .history-empty").forEach(el => el.remove());

    if (!history.length) {
      const empty = document.createElement("div");
      empty.className = "history-empty";
      empty.innerHTML = '<span><svg aria-hidden="true" class="icon" fill="none" height="24" viewBox="0 0 24 24" width="24"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path></svg></span><h4>Belum ada riwayat pemeriksaan</h4><p>URL yang kamu periksa akan muncul di sini.</p>';
      historyList.appendChild(empty);
      return;
    }

    history.forEach(item => {
      const row = document.createElement("article");
      row.className = "history-row";
      row.innerHTML = `<div class="history-row__url"><span>${iconSvg("check")}</span><div><strong></strong><small></small></div></div><span class="history-row__time"></span><span class="history-status history-status--${item.status}">${item.status === "safe" ? "Tanpa indikasi" : item.status === "warning" ? "Perlu diperiksa" : "Mencurigakan"} <small>DEMO</small></span>`;
      row.querySelector("strong").textContent = item.url;
      row.querySelector("small").textContent = item.title;
      row.querySelector(".history-row__time").textContent = item.time;
      historyList.appendChild(row);
    });
  }

  function updateStats() {
    if (stats.total) stats.total.textContent = counts.total;
    if (stats.safe) stats.safe.textContent = counts.safe;
    if (stats.warning) stats.warning.textContent = counts.warning;
    if (stats.danger) stats.danger.textContent = counts.danger;
  }

  form?.addEventListener("submit", event => {
    event.preventDefault();
    const url = input.value.trim();

    if (!url) {
      input.setAttribute("aria-invalid", "true");
      input.focus();
      updateResult("-", {
        status: "error",
        title: "URL belum diisi",
        description: "Masukkan alamat URL terlebih dahulu untuk menjalankan simulasi.",
        reasons: ["Kolom URL tidak boleh kosong."]
      });
      return;
    }

    input.setAttribute("aria-invalid", "false");
    const assessment = assessUrl(url);
    const normalized = (() => {
      try { return new URL(url.includes("://") ? url : `https://${url}`).href; }
      catch { return url; }
    })();

    updateResult(normalized, assessment);
    counts.total += 1;
    counts[assessment.status] += 1;
    updateStats();

    history.unshift({
      url: normalized,
      status: assessment.status,
      title: assessment.title,
      time: new Date().toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" })
    });
    history = history.slice(0, 8);
    renderHistory();
    result?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  });

  clearButton?.addEventListener("click", () => {
    history = [];
    counts = { total: 0, safe: 0, warning: 0, danger: 0 };
    updateStats();
    renderHistory();
  });

  // Ubah tautan navigasi agar menuju bagian di halaman lokal, bukan alamat situs asal.
  document.querySelectorAll('a[href*="#"]').forEach(link => {
    const hash = link.getAttribute("href")?.match(/#.+$/)?.[0];
    if (hash) link.setAttribute("href", hash);
  });

  // Reset contoh statis dari file HTML agar dashboard mulai dari nol.
  updateStats();
  renderHistory();
});
