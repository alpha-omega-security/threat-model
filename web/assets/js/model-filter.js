(() => {
  const search = document.querySelector("[data-model-search]");
  const status = document.querySelector("[data-model-status]");
  const cards = [...document.querySelectorAll("[data-model-card]")];
  const empty = document.querySelector("[data-model-empty]");

  if (!search || !status || cards.length === 0) return;

  const filter = () => {
    const query = search.value.trim().toLowerCase();
    const selectedStatus = status.value;
    let visible = 0;

    cards.forEach((card) => {
      const matchesQuery = !query || card.dataset.search.includes(query);
      const matchesStatus = !selectedStatus || card.dataset.status === selectedStatus;
      const show = matchesQuery && matchesStatus;
      card.hidden = !show;
      if (show) visible += 1;
    });

    if (empty) empty.hidden = visible !== 0;
  };

  search.addEventListener("input", filter);
  status.addEventListener("change", filter);
})();

