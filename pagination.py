"""Shared pagination window helpers for server templates and tests."""

from __future__ import annotations

ELLIPSIS = '...'


def build_page_items(current_page: int, total_pages: int) -> list[int | str]:
    """Return page numbers with ellipsis markers, always including the last page."""
    if total_pages <= 0:
        return []
    if total_pages == 1:
        return [1]

    current_page = max(1, min(int(current_page), int(total_pages)))

    if total_pages <= 5:
        return list(range(1, total_pages + 1))

    if current_page <= 3:
        return [1, 2, 3, ELLIPSIS, total_pages]

    if current_page >= total_pages - 2:
        return [1, ELLIPSIS, total_pages - 2, total_pages - 1, total_pages]

    return [1, ELLIPSIS, current_page - 1, current_page, current_page + 1, ELLIPSIS, total_pages]
