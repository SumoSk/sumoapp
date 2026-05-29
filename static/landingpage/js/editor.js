const postForm = document.getElementById("postForm");

function makeSlug(text) {
  return String(text || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9ก-๙]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function togglePostTypeUI() {
  const select = document.getElementById("postTypeSelect");
  const beautyFields = document.querySelectorAll(".beauty-only-fields");

  if (!select) return;

  const isBeauty = select.value === "beauty";

  beautyFields.forEach((el) => {
    el.style.display = isBeauty ? "" : "none";
  });
}

if (postForm) {
  const titleInput = postForm.querySelector('input[name="title"]');
  const slugInput = postForm.querySelector('input[name="slug"]');
  const postTypeSelect = document.getElementById("postTypeSelect");

  if (titleInput && slugInput) {
    titleInput.addEventListener("blur", () => {
      if (!slugInput.value.trim()) {
        slugInput.value = makeSlug(titleInput.value);
      }
    });
  }

  if (postTypeSelect) {
    postTypeSelect.addEventListener("change", togglePostTypeUI);
    togglePostTypeUI();
  }

  postForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const submitBtn = postForm.querySelector('button[type="submit"]');
    const oldText = submitBtn ? submitBtn.textContent : "";

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "กำลังบันทึก...";
    }

    try {
      const fd = new FormData(postForm);

      const res = await fetch("/api/site/posts/save", {
        method: "POST",
        body: fd
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        throw new Error(data.error || "บันทึกไม่สำเร็จ");
      }

      alert("บันทึกบทความสำเร็จ");

      if (data.url) {
        window.location.href = data.url;
      } else {
        window.location.href = "/articles/";
      }
    } catch (err) {
      alert(err.message || "เกิดข้อผิดพลาด");
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = oldText || "บันทึก";
      }
    }
  });
}
