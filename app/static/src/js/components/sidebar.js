const FAVORITES_KEY = "analisa:favorites";
const RECENT_KEY = "analisa:recent-tools";
const COLLAPSED_KEY = "analisa:sidebar-collapsed";
const CATEGORY_STATE_KEY = "analisa:sidebar-categories";
const MAX_RECENT = 8;

function readJSON(key, fallback) {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch (err) {
    return fallback;
  }
}

function writeJSON(key, value) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch (err) {
    /* localStorage indisponível (modo privado, cota etc.) — ignora silenciosamente */
  }
}

export function sidebar() {
  return {
    collapsed: readJSON(COLLAPSED_KEY, false),
    drawerOpen: false,
    query: "",
    favorites: readJSON(FAVORITES_KEY, []),
    recent: readJSON(RECENT_KEY, []),
    openCategories: readJSON(CATEGORY_STATE_KEY, {}),

    init() {
      const active = this.$el.querySelector("[data-active-category]");
      if (active) {
        const slug = active.getAttribute("data-active-category");
        this.openCategories[slug] = true;
      }
    },

    toggleCollapsed() {
      this.collapsed = !this.collapsed;
      writeJSON(COLLAPSED_KEY, this.collapsed);
    },

    toggleCategory(slug) {
      this.openCategories[slug] = !this.openCategories[slug];
      writeJSON(CATEGORY_STATE_KEY, this.openCategories);
    },

    isCategoryOpen(slug) {
      return Boolean(this.openCategories[slug]);
    },

    isFavorite(slug) {
      return this.favorites.includes(slug);
    },

    toggleFavorite(slug) {
      if (this.favorites.includes(slug)) {
        this.favorites = this.favorites.filter((s) => s !== slug);
      } else {
        this.favorites = [...this.favorites, slug];
      }
      writeJSON(FAVORITES_KEY, this.favorites);
    },

    registerRecent(slug) {
      const next = [slug, ...this.recent.filter((s) => s !== slug)].slice(0, MAX_RECENT);
      this.recent = next;
      writeJSON(RECENT_KEY, next);
    },

    matchesQuery(name, keywords) {
      if (!this.query) return true;
      const q = this.query.toLowerCase();
      return (
        name.toLowerCase().includes(q) ||
        (keywords || "").toLowerCase().includes(q)
      );
    },
  };
}
