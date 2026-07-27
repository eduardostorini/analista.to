"""Nomes de task Celery, compartilhados entre quem enfileira (services) e
quem define a task (app/tasks/*), evitando import circular entre eles.
"""
RUN_SEARCH_TASK = "app.tasks.search_tasks.run_search"
GENERATE_PAGE_TASK = "app.tasks.page_tasks.generate_page"
REGENERATE_SITEMAPS_TASK = "app.tasks.sitemap_tasks.regenerate_sitemaps"
CLEANUP_EXPIRED_TASK = "app.tasks.maintenance_tasks.cleanup_expired_searches"
